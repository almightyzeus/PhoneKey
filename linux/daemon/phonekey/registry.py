"""Paired-device registry: one JSON file per device, keyed by device_id.

Records are re-read from disk on every lookup, so `phonekey unpair` takes effect
immediately, even for a running daemon. A record whose device_id does not match
its public key is treated as corrupt and ignored.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from . import crypto
from .codec import KeySecurity

log = logging.getLogger(__name__)

_FILENAME = re.compile(r"^[0-9a-f]{64}\.json$")
MIN_PREFIX = 4


@dataclass(frozen=True)
class DeviceRecord:
    device_id: bytes
    public_key: bytes  # DER SubjectPublicKeyInfo
    account: str
    display_name: str
    paired_at: str  # ISO 8601, UTC
    key_security: KeySecurity
    attestation: str  # informational summary only (SECURITY.md D-5)
    bond_address: str | None = None  # metadata only, never identity

    def __post_init__(self) -> None:
        crypto.load_public_key(self.public_key)
        if crypto.key_id(self.public_key) != self.device_id:
            raise ValueError("device_id does not match public key")

    def to_json(self) -> dict:
        d = asdict(self)
        d["device_id"] = self.device_id.hex()
        d["public_key"] = self.public_key.hex()
        d["key_security"] = self.key_security.name
        return d

    @classmethod
    def from_json(cls, d: dict) -> DeviceRecord:
        return cls(
            device_id=bytes.fromhex(d["device_id"]),
            public_key=bytes.fromhex(d["public_key"]),
            account=str(d["account"]),
            display_name=str(d["display_name"]),
            paired_at=str(d["paired_at"]),
            key_security=KeySecurity[d["key_security"]],
            attestation=str(d["attestation"]),
            bond_address=d.get("bond_address"),
        )


class Registry:
    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir) / "devices"

    def _path(self, device_id: bytes) -> Path:
        return self.dir / f"{device_id.hex()}.json"

    def _load(self, path: Path) -> DeviceRecord | None:
        try:
            record = DeviceRecord.from_json(json.loads(path.read_text()))
        except FileNotFoundError:
            return None
        except (ValueError, KeyError, TypeError) as e:
            log.warning("ignoring corrupt device record %s: %s", path.name, e)
            return None
        if path.name != f"{record.device_id.hex()}.json":
            log.warning("ignoring device record with mismatched file name %s", path.name)
            return None
        return record

    def get(self, device_id: bytes) -> DeviceRecord | None:
        return self._load(self._path(device_id))

    def all(self) -> list[DeviceRecord]:
        if not self.dir.is_dir():
            return []
        records = (self._load(p) for p in sorted(self.dir.iterdir()) if _FILENAME.match(p.name))
        return [r for r in records if r is not None]

    def for_account(self, account: str) -> list[DeviceRecord]:
        return [r for r in self.all() if r.account == account]

    def find(self, prefix: str) -> DeviceRecord:
        """Finds exactly one device by device_id hex prefix (spaces ignored)."""
        prefix = prefix.replace(" ", "").lower()
        if len(prefix) < MIN_PREFIX or not re.fullmatch(r"[0-9a-f]+", prefix):
            raise ValueError(f"device id prefix must be at least {MIN_PREFIX} hex digits")
        matches = [r for r in self.all() if r.device_id.hex().startswith(prefix)]
        if not matches:
            raise LookupError(f"no paired device matches {prefix}")
        if len(matches) > 1:
            raise LookupError(f"{prefix} matches {len(matches)} devices; use a longer prefix")
        return matches[0]

    def add(self, record: DeviceRecord) -> None:
        """Stores a record atomically (replacing a record for the same device)."""
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "w") as f:  # mkstemp creates the file with mode 0600
                json.dump(record.to_json(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path(record.device_id))
        except BaseException:
            os.unlink(tmp)
            raise

    def remove(self, device_id: bytes) -> bool:
        try:
            self._path(device_id).unlink()
            return True
        except FileNotFoundError:
            return False
