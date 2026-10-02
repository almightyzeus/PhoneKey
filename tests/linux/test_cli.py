"""`phonekey` CLI behaviour (subprocess, isolated state directory)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from phonekey.registry import Registry
from tests.helpers import ROOT
from tests.linux.test_registry import make_record

CLI = ROOT / "linux" / "cli" / "phonekey"


class CliTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "PHONEKEY_STATE_DIR": str(self.state),
               "PHONEKEY_SOCKET": str(self.state / "no-daemon.sock")}
        return subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, env=env,
                              timeout=60)

    def test_simulated_test_succeeds_and_rejects_attacks(self):
        result = self.run_cli("test", "--simulate")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("✓ PhoneKey authentication successful", result.stdout)
        self.assertNotIn("✗", result.stdout)
        for check in ("replayed response rejected", "tampered signature rejected",
                      "modified request rejected", "unknown phone rejected"):
            self.assertIn(f"✓ {check}", result.stdout)

    def test_simulation_never_touches_real_registry(self):
        self.run_cli("test", "--simulate")
        self.assertFalse((self.state / "devices").exists())
        self.assertEqual([], list(self.state.iterdir()))

    def test_test_without_daemon_explains(self):
        result = self.run_cli("test")
        self.assertEqual(2, result.returncode)
        self.assertIn("phonekeyd is not running", result.stderr)

    def test_status_and_devices_with_empty_registry(self):
        status = self.run_cli("status")
        self.assertEqual(0, status.returncode)
        self.assertIn("Paired devices: 0", status.stdout)
        self.assertIn("No paired devices.", self.run_cli("devices").stdout)

    def test_unpair_by_prefix_and_all(self):
        registry = Registry(self.state)
        a, b, c = make_record(name="A"), make_record(name="B"), make_record(name="C")
        for r in (a, b, c):
            registry.add(r)
        self.assertIn("Paired devices: 3", self.run_cli("status").stdout)

        result = self.run_cli("unpair", a.device_id.hex()[:10])
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIsNone(registry.get(a.device_id))

        self.assertEqual(1, self.run_cli("unpair", "0").returncode)  # prefix too short

        self.assertEqual(0, self.run_cli("unpair", "--all").returncode)
        self.assertEqual([], registry.all())


if __name__ == "__main__":
    unittest.main()


class DoctorTest(unittest.TestCase):
    """`phonekey doctor`: read-only facts and hints (docs/RELIABILITY.md, condition 24)."""

    KERNEL = (
        "2026-10-02T21:47:03+05:30 host kernel: Bluetooth: hci0: Opcode 0x2042 failed: -110\n"
        "2026-10-02T21:47:03+05:30 host kernel: Bluetooth: hci0: Unable to disable scanning: -110\n"
        "2026-10-02T21:57:30+05:30 host kernel: Bluetooth: hci0: Opcode 0x0c03 failed: -110\n"
        "2026-10-02T21:58:10+05:30 host kernel: Bluetooth: hci0: AOSP extensions version v1.00\n"
    )

    def test_counts_one_line_per_controller_timeout(self):
        from phonekey.cli import controller_timeouts
        self.assertEqual((2, "2026-10-02T21:57:30+05:30"), controller_timeouts(self.KERNEL))
        self.assertEqual((0, None), controller_timeouts(""))

    def test_hints(self):
        from phonekey.cli import diagnose
        ok = {"service": "active", "adapters": [{"name": "hci0", "powered": True, "discovering": False}],
              "paired": [{"name": "p", "device_id": "00", "connected": True}], "controller_stuck": 0}
        self.assertEqual([], diagnose(ok))
        self.assertIn("not running", " ".join(diagnose({**ok, "service": "inactive"})))
        self.assertIn("Bluetooth is off", " ".join(diagnose({**ok, "adapters": [{**ok["adapters"][0], "powered": False}]})))
        self.assertIn("did not answer 3", " ".join(diagnose({**ok, "controller_stuck": 3, "controller_stuck_last": "t"})))
        self.assertIn("not connected", " ".join(diagnose({**ok, "paired": [{**ok["paired"][0], "connected": False}]})))
        self.assertIn("Scanning is on", " ".join(diagnose({**ok, "adapters": [{**ok["adapters"][0], "discovering": True}]})))

    def test_runs_without_a_daemon(self):
        env = {**os.environ, "PHONEKEY_SOCKET": "/nonexistent/phonekey.sock"}
        result = subprocess.run([sys.executable, str(CLI), "doctor"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Daemon: not answering", result.stdout)
