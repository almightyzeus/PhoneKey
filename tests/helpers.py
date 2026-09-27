"""Shared fixtures for the Linux/protocol tests. Run via scripts/linux-tests.sh."""

import tempfile
import unittest
from pathlib import Path

from phonekey import crypto
from phonekey.registry import Registry
from phonekey.simulator import SimulatedAuthenticator
from phonekey.verifier import Verifier

ROOT = Path(__file__).resolve().parent.parent
ACCOUNT = "alice"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class VerifierTestCase(unittest.TestCase):
    """A verifier with a temporary registry and one paired simulated phone."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name)
        self.clock = FakeClock()
        self.verifier = self.make_verifier()
        self.phone = SimulatedAuthenticator()
        self.pair(self.phone)

    def make_verifier(self, **kwargs) -> Verifier:
        kwargs.setdefault("allow_software_keys", True)  # the simulator's key is software
        return Verifier(crypto.generate_key(), Registry(self.state_dir), display_name="test-host",
                        clock=self.clock, **kwargs)

    def pair(self, phone: SimulatedAuthenticator, account: str = ACCOUNT):
        return self.verifier.complete_pairing(phone.handle_pair_request(self.verifier.begin_pairing(account=account)))

    def request(self, device_id: bytes | None = None, account: str = ACCOUNT, action: str = "linux.sudo",
                detail: str | None = None):
        return self.verifier.begin_auth(device_id or self.phone.device_id, account=account, action=action,
                                        resource="test-host", detail=detail)
