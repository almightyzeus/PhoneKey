"""The sudo command shown on the phone (SECURITY.md R-8, D-13)."""

import os
import tempfile
import unittest
from pathlib import Path

from phonekey import codec, command
from phonekey.codec import MsgType


def fake_proc(root: Path, pid: int, comm: str, argv: list[bytes]) -> None:
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "comm").write_text(comm + "\n")
    (d / "cmdline").write_bytes(b"\0".join(argv) + b"\0")


def encodable(text: str) -> bool:
    """The text fits the AUTH_REQUEST detail field (length, no forbidden characters)."""
    try:
        codec.encode_unsigned(MsgType.AUTH_REQUEST, {
            "verifier_id": bytes(32), "device_id": bytes(32), "request_id": bytes(16), "challenge": bytes(32),
            "action": "linux.sudo", "resource": "h", "account": "a", "issued_at": 0, "ttl_ms": 1,
            "detail": text})
        return True
    except (codec.ProtocolError, ValueError, TypeError):
        return False


class DescribeTest(unittest.TestCase):
    def test_plain_command(self):
        self.assertEqual(command.describe("sudo", [b"apt", b"upgrade"]), "sudo apt upgrade")

    def test_arguments_are_quoted_unambiguously(self):
        self.assertEqual(command.describe("sudo", [b"rm", b"a b", b"; reboot"]), "sudo rm 'a b' '; reboot'")

    def test_control_and_bidi_characters_are_escaped(self):
        text = command.describe("sudo", [b"echo", b"a\nb", "x\u202ey".encode(), b"\x1b[2J"])
        self.assertNotIn("\n", text)
        self.assertIn("\\n", text)
        self.assertIn("\\u202e", text)
        self.assertIn("\\u001b", text)
        self.assertTrue(encodable(text))

    def test_invalid_utf8_is_visible(self):
        text = command.describe("sudo", [b"cat", b"\xff\xfe"])
        self.assertIn("\\xff", text)
        self.assertTrue(encodable(text))

    def test_long_commands_are_truncated_visibly(self):
        args = [b"sh", b"-c", b"apt upgrade" + b" " * 400 + b"; rm -rf /"]
        text = command.describe("sudo", args)
        self.assertLessEqual(len(text.encode()), command.MAX_BYTES)
        self.assertRegex(text, r" … \[\+\d+ more characters\]$")
        self.assertTrue(encodable(text))

    def test_truncation_respects_multibyte_characters(self):
        for n in range(80, 140):
            text = command.describe("sudo", [("é" * n).encode()])
            self.assertLessEqual(len(text.encode()), command.MAX_BYTES)
            self.assertTrue(encodable(text), n)

    def test_exact_limit_is_not_truncated(self):
        arg = "x" * (command.MAX_BYTES - len("sudo "))
        self.assertEqual(command.describe("sudo", [arg.encode()]), "sudo " + arg)


class SudoCommandTest(unittest.TestCase):
    def setUp(self):
        self.proc = Path(tempfile.mkdtemp())

    def test_reads_sudo_argv(self):
        fake_proc(self.proc, 42, "sudo", [b"sudo", b"-u", b"bob", b"id"])
        self.assertEqual(command.sudo_command(42, self.proc), "sudo -u bob id")

    def test_sudoedit(self):
        fake_proc(self.proc, 43, "sudoedit", [b"sudoedit", b"/etc/hosts"])
        self.assertEqual(command.sudo_command(43, self.proc), "sudoedit /etc/hosts")

    def test_argv0_path_is_not_shown(self):
        fake_proc(self.proc, 44, "sudo", [b"/usr/bin/sudo", b"true"])
        self.assertEqual(command.sudo_command(44, self.proc), "sudo true")

    def test_other_processes_get_no_detail(self):
        fake_proc(self.proc, 45, "python3", [b"sudo", b"apt", b"upgrade"])  # argv[0] can lie; comm is checked
        self.assertIsNone(command.sudo_command(45, self.proc))

    def test_missing_process(self):
        self.assertIsNone(command.sudo_command(99999, self.proc))

    def test_own_process_is_readable(self):
        self.assertIsNone(command.sudo_command(os.getpid()))  # real /proc, not sudo


if __name__ == "__main__":
    unittest.main()
