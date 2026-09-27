"""pam_phonekey.so against a fake phonekeyd, through real libpam.

Stacks come from a private directory (pam_start_confdir), never /etc/pam.d.
Needs the PAM headers: libpam0g-dev, or PHONEKEY_PAM_INCLUDE pointing at
headers extracted with `apt-get download libpam0g-dev` (see linux/pam/Makefile).
PHONEKEY_PAM_SANITIZE=1 builds both with AddressSanitizer/UBSan.
"""

import getpass
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAM_DIR = ROOT / "linux" / "pam"
INCLUDE = os.environ.get("PHONEKEY_PAM_INCLUDE", "/usr/include")
LIBPAM = "/usr/lib/x86_64-linux-gnu/libpam.so.0"
USER = getpass.getuser()
HAVE_HEADERS = Path(INCLUDE, "security", "pam_modules.h").exists() and Path(LIBPAM).exists()


def build(out: Path) -> tuple[Path, Path]:
    flags = ["-O1", "-g", "-Wall", "-Wextra", "-Werror", "-I", INCLUDE]
    if os.environ.get("PHONEKEY_PAM_SANITIZE"):
        flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    module, harness = out / "pam_phonekey.so", out / "pam_harness"
    subprocess.run(["cc", *flags, "-fPIC", "-fvisibility=hidden", "-shared", "-o", module,
                    PAM_DIR / "pam_phonekey.c", LIBPAM], check=True)
    subprocess.run(["cc", *flags, "-o", harness, PAM_DIR / "pam_harness.c", LIBPAM], check=True)
    return module, harness


class FakeDaemon:
    """Accepts one connection per scripted reply; records the requests."""

    def __init__(self, path: Path, script):
        self.path, self.script, self.requests = path, script, []
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(4)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(5)
            try:
                self.requests.append(conn.makefile("rb").readline())
                self.script(conn)
            except OSError:
                pass

    def close(self):
        self.sock.close()


def lines(*events):
    def script(conn):
        for event in events:
            conn.sendall(event if isinstance(event, bytes) else json.dumps(event).encode() + b"\n")
    return script


@unittest.skipUnless(HAVE_HEADERS, "PAM headers not available (see linux/pam/Makefile)")
class PamModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="pk-pam-"))
        cls.module, cls.harness = build(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=self.tmp))
        self.socket = self.dir / "sock"
        self.daemon = None

    def tearDown(self):
        if self.daemon:
            self.daemon.close()

    def run_stack(self, *, args=None, user=USER, module=None, fallback="pam_deny.so", timeout=15):
        args = args if args is not None else f"action=sudo socket={self.socket} daemon_user={USER} timeout=5"
        (self.dir / "svc").write_text(
            f"auth sufficient {module or self.module} {args}\n"
            f"auth requisite {fallback}\n")
        start = time.monotonic()
        proc = subprocess.run([self.harness, self.dir, "svc", user], capture_output=True, text=True,
                              timeout=timeout)
        self.assertNotIn("Sanitizer", proc.stderr)
        return proc.returncode, proc.stdout, time.monotonic() - start

    def serve(self, script):
        self.daemon = FakeDaemon(self.socket, script)

    # ---- results ------------------------------------------------------------

    def test_approved(self):
        self.serve(lines({"event": "sent", "device": "phone"}, {"result": "ok"}))
        code, out, _ = self.run_stack()
        self.assertEqual(code, 0, out)
        self.assertIn("confirm on your phone", out)
        self.assertEqual(json.loads(self.daemon.requests[0]),
                         {"op": "auth", "action": "sudo", "account": USER})

    def test_denied_falls_through(self):
        self.serve(lines({"event": "sent", "device": "phone"}, {"result": "denied", "reason": "USER_DENIED"}))
        code, out, _ = self.run_stack()
        self.assertEqual(code, 1)
        self.assertIn("denied on the phone", out)

    def test_denied_then_password_module_succeeds(self):
        self.serve(lines({"result": "denied", "reason": "USER_DENIED"}))
        code, _, _ = self.run_stack(fallback="pam_permit.so")
        self.assertEqual(code, 0)  # stands in for the password prompt: still reachable

    def test_unavailable_is_fast(self):
        self.serve(lines({"result": "unavailable", "reason": "no paired phone connected"}))
        code, out, elapsed = self.run_stack()
        self.assertEqual(code, 1)
        self.assertNotIn("confirm on your phone", out)
        self.assertLess(elapsed, 2)

    def test_error_result(self):
        self.serve(lines({"result": "error", "reason": "BAD_SIGNATURE"}))
        self.assertEqual(self.run_stack()[0], 1)

    def test_other_results_are_not_success(self):
        for value in ("OK", "ok ", "okay", "", "paired"):
            with self.subTest(value=value):
                self.tearDown()
                self.setUp()
                self.serve(lines({"result": value}))
                self.assertEqual(self.run_stack()[0], 1)

    def test_ok_inside_another_string_is_not_success(self):
        self.serve(lines({"event": "sent", "device": 'x", "result": "ok'}))  # json.dumps escapes the quotes
        self.assertEqual(self.run_stack()[0], 1)

    # ---- the daemon misbehaves or is absent ---------------------------------------

    def test_no_daemon_is_fast(self):
        code, _, elapsed = self.run_stack()
        self.assertEqual(code, 1)
        self.assertLess(elapsed, 2)

    def test_socket_owned_by_another_user_is_not_used(self):
        self.serve(lines({"result": "ok"}))
        code, _, _ = self.run_stack(args=f"action=sudo socket={self.socket} daemon_user=root timeout=2")
        self.assertEqual(code, 1)
        time.sleep(0.2)
        self.assertEqual([r for r in self.daemon.requests if r], [])  # hung up without sending

    def test_silent_daemon_times_out(self):
        self.serve(lambda conn: time.sleep(4))
        code, out, elapsed = self.run_stack(args=f"action=sudo socket={self.socket} daemon_user={USER} timeout=1")
        self.assertEqual(code, 1)
        self.assertIn("no answer", out)
        self.assertLess(elapsed, 3)

    def test_daemon_closes_without_result(self):
        self.serve(lines({"event": "sent", "device": "phone"}))
        self.assertEqual(self.run_stack()[0], 1)

    def test_oversized_reply(self):
        self.serve(lines(b"x" * 100_000))
        self.assertEqual(self.run_stack()[0], 1)

    def test_split_and_garbage_lines(self):
        def script(conn):
            for chunk in (b'\x00\xff{not json\n{"eve', b'nt": "sent"}\n{"resu', b'lt": "ok"}\n'):
                conn.sendall(chunk)
                time.sleep(0.05)
        self.serve(script)
        self.assertEqual(self.run_stack()[0], 0)

    # ---- configuration and input --------------------------------------------------

    def test_bad_options_never_succeed(self):
        self.serve(lines({"result": "ok"}))
        for args in (f"socket={self.socket} daemon_user={USER}",  # no action
                     f"action=root socket={self.socket} daemon_user={USER}",
                     f"action=sudo timeout=0 socket={self.socket} daemon_user={USER}",
                     f"action=sudo bogus socket={self.socket} daemon_user={USER}"):
            with self.subTest(args=args):
                self.assertEqual(self.run_stack(args=args)[0], 1)
        self.assertEqual(self.daemon.requests, [])

    def test_unsafe_user_name_is_not_sent(self):
        self.serve(lines({"result": "ok"}))
        for user in ('a"b', "a b", "-x", "a\\b", "x" * 65):
            with self.subTest(user=user):
                self.assertEqual(self.run_stack(user=user)[0], 1)
        self.assertEqual(self.daemon.requests, [])

    def test_missing_module_does_not_block_the_stack(self):
        code, _, _ = self.run_stack(module=self.dir / "missing.so", fallback="pam_permit.so")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
