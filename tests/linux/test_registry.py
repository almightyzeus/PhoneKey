"""Paired-device registry storage (SECURITY.md §3 assets, T-8)."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from phonekey import crypto
from phonekey.codec import KeySecurity
from phonekey.registry import DeviceRecord, Registry


def make_record(account="alice", name="Pixel") -> DeviceRecord:
    spki = crypto.spki_of(crypto.generate_key().public_key())
    return DeviceRecord(device_id=crypto.key_id(spki), public_key=spki, account=account, display_name=name,
                        paired_at="2026-09-27T00:00:00+00:00", key_security=KeySecurity.TEE,
                        attestation="not provided", bond_address="AA:BB:CC:DD:EE:FF")


class RegistryTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.state = Path(tmp.name)
        self.registry = Registry(self.state)

    def test_roundtrip_through_disk(self):
        record = make_record()
        self.registry.add(record)
        self.assertEqual(record, Registry(self.state).get(record.device_id))
        self.assertEqual([record], self.registry.all())

    def test_permissions(self):
        record = make_record()
        self.registry.add(record)
        self.assertEqual(0o700, stat.S_IMODE(os.stat(self.registry.dir).st_mode))
        path = self.registry.dir / f"{record.device_id.hex()}.json"
        self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))

    def test_no_temp_files_left(self):
        self.registry.add(make_record())
        self.assertEqual([], [p for p in self.registry.dir.iterdir() if p.name.startswith(".tmp")])

    def test_empty_registry(self):
        self.assertEqual([], self.registry.all())
        self.assertIsNone(self.registry.get(bytes(32)))

    def test_record_must_match_its_key(self):
        record = make_record()
        with self.assertRaises(ValueError):
            DeviceRecord(**{**record.__dict__, "device_id": bytes(32)})

    def test_tampered_record_is_ignored(self):
        victim, attacker = make_record(), make_record()
        self.registry.add(victim)
        path = self.registry.dir / f"{victim.device_id.hex()}.json"
        data = json.loads(path.read_text())
        data["public_key"] = attacker.public_key.hex()  # swap in another key
        path.write_text(json.dumps(data))
        with self.assertLogs("phonekey.registry", "WARNING"):
            self.assertIsNone(self.registry.get(victim.device_id))

    def test_record_under_wrong_file_name_is_ignored(self):
        record = make_record()
        self.registry.add(record)
        src = self.registry.dir / f"{record.device_id.hex()}.json"
        src.rename(self.registry.dir / f"{'0' * 64}.json")
        with self.assertLogs("phonekey.registry", "WARNING"):
            self.assertEqual([], self.registry.all())

    def test_unrelated_files_ignored(self):
        self.registry.add(make_record())
        (self.registry.dir / "notes.txt").write_text("x")
        self.assertEqual(1, len(self.registry.all()))

    def test_for_account(self):
        a, b = make_record("alice"), make_record("bob")
        self.registry.add(a)
        self.registry.add(b)
        self.assertEqual([a], self.registry.for_account("alice"))

    def test_find_by_prefix(self):
        record = make_record()
        self.registry.add(record)
        hexid = record.device_id.hex()
        self.assertEqual(record, self.registry.find(hexid[:8]))
        self.assertEqual(record, self.registry.find(f"{hexid[:4]} {hexid[4:8]}".upper()))
        with self.assertRaises(ValueError):
            self.registry.find(hexid[:3])
        with self.assertRaises(ValueError):
            self.registry.find("zzzz")
        with self.assertRaises(LookupError):
            self.registry.find("ffff" if not hexid.startswith("ffff") else "0000")

    def test_ambiguous_prefix(self):
        records = [make_record() for _ in range(40)]
        for r in records:
            self.registry.add(r)
        first = records[0].device_id.hex()
        shared = [r for r in records if r.device_id.hex()[0] == first[0]]
        if len(shared) > 1:
            with self.assertRaises(ValueError):  # 1 char is below the minimum anyway
                self.registry.find(first[0])

    def test_remove(self):
        record = make_record()
        self.registry.add(record)
        self.assertTrue(self.registry.remove(record.device_id))
        self.assertFalse(self.registry.remove(record.device_id))
        self.assertIsNone(self.registry.get(record.device_id))


class VerifierKeyTest(unittest.TestCase):
    def test_created_with_0600_and_reloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "verifier_key.pem"
            key = crypto.load_or_create_key(path)
            self.assertEqual(0o600, stat.S_IMODE(os.stat(path).st_mode))
            again = crypto.load_or_create_key(path)
            self.assertEqual(crypto.spki_of(key.public_key()), crypto.spki_of(again.public_key()))


if __name__ == "__main__":
    unittest.main()
