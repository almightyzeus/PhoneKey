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
        env = {**os.environ, "PHONEKEY_STATE_DIR": str(self.state)}
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

    def test_test_without_simulate_explains_phase(self):
        result = self.run_cli("test")
        self.assertEqual(2, result.returncode)
        self.assertIn("Phase 3", result.stderr)

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
