"""Phase 7 reliability checks on the daemon core (docs/RELIABILITY.md, conditions 12, 19, 21, 22).

The chaos test drives DaemonCore through long random sequences of link events,
requests, cancellations, timer firings and bad input, and checks that every
request ends exactly once, nothing stays pending or busy, and PhoneKey works
again afterwards. Seeds are fixed, so a failure is reproducible.
"""

import random
import unittest

from phonekey import codec, framing
from phonekey.codec import MsgType
from phonekey.core import DaemonCore
from phonekey.simulator import SimulatedAuthenticator
from phonekey.verifier import Verifier
from tests.helpers import ACCOUNT
from tests.linux.test_core import CoreTestCase, FakePhone

ACTIONS = ("phonekey.test", "linux.sudo", "linux.unlock")
SEEDS = range(40)
STEPS = 250


class Request:
    """One local caller (sudo, lock screen, `phonekey test`)."""

    def __init__(self):
        self.events = []
        self.request_id = None
        self.cancelled = False

    def finals(self):
        return [e for e in self.events if "result" in e]


class ResilienceTestCase(CoreTestCase):
    def quiesce(self):
        """Every phone disconnects, then time passes until no timer is left."""
        for phone in list(self.transport.phones):
            self.disconnect(phone)
        for _ in range(100):
            if not self.scheduler.timers:
                return
            self.scheduler.fire_all()
        self.fail(f"timers keep rescheduling: {self.scheduler.timers}")

    def assert_idle(self):
        self.assertEqual({}, self.core._waiters, "a request is still waiting")
        self.assertEqual(0, self.verifier.pending_count, "a challenge is still pending")
        self.assertIsNone(self.core._pairing, "a pairing window is still open")
        self.assertFalse(self.transport.pairing_mode, "BLE still in pairing mode")
        self.assertEqual(set(), self.core.connected_device_ids())

    def assert_works_again(self):
        phone = self.connect(self.phone)
        phone.approve = phone.auto_reply = phone.keepalive = True
        result = []
        self.core.authenticate(ACCOUNT, "phonekey.test", "test-host", result.append)
        self.assertEqual({"result": "ok"}, result[-1], "PhoneKey did not recover")


class ChaosTest(ResilienceTestCase):
    """Conditions 21 (no deadlocks) and 22 (no permanently stuck state)."""

    def test_random_event_sequences_never_leave_stuck_state(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                self.setUp()
                try:
                    self.run_chaos(random.Random(seed))
                finally:
                    self.doCleanups()

    def run_chaos(self, rng: random.Random):
        stranger = SimulatedAuthenticator("Unpaired phone")
        peers = ["/org/bluez/hci0/dev_AA_00_00_00_00_01", "/org/bluez/hci0/dev_AA_00_00_00_00_02"]
        requests: list[Request] = []
        msg_no = 200

        def live(peer):
            return next((p for p in self.transport.phones if p.peer_id == peer), None)

        for _ in range(STEPS):
            choice = rng.randrange(13)
            peer = rng.choice(peers)
            phone = live(peer)
            if choice == 0 and phone is None:
                phone = self.connect(rng.choice([self.phone, self.phone, stranger]), peer_id=peer,
                                     hello=rng.random() < 0.8)
            elif choice == 1 and phone is not None:
                self.disconnect(phone)
                # Requests for a phone with no link left fail at once, not at their timeout.
                gone = {w.device_id for w in self.core._waiters.values()} - self.core.connected_device_ids()
                self.assertEqual(set(), gone, "request kept waiting for a disconnected phone")
            elif choice in (2, 3):  # a local caller asks
                req = Request()
                req.request_id = self.core.authenticate(ACCOUNT, rng.choice(ACTIONS), "test-host", req.events.append)
                requests.append(req)
            elif choice == 4:  # a caller gives up (lock screen timeout, Ctrl-C)
                waiting = [r for r in requests if r.request_id and not r.finals() and not r.cancelled]
                if waiting:
                    req = rng.choice(waiting)
                    req.cancelled = True
                    self.core.cancel_auth(req.request_id)
            elif choice in (5, 6) and self.scheduler.timers:  # time passes for one timer
                handle = rng.choice(list(self.scheduler.timers))
                _, callback = self.scheduler.timers.pop(handle)
                callback()
            elif choice == 7 and phone is not None:  # the phone's behaviour changes
                phone.approve = rng.random() < 0.7
                phone.auto_reply = rng.random() < 0.7
                phone.keepalive = rng.random() < 0.8
            elif choice == 8 and phone is not None and phone.held:  # a late answer arrives
                phone.send(phone.held.pop(rng.randrange(len(phone.held))))
            elif choice == 9 and phone is not None:  # garbage on the link
                self.core.on_frame(peer, bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40))))
            elif choice == 10 and phone is not None:  # first half of a message, never finished
                msg_no = (msg_no + 1) & 0xFF
                big = codec.encode(MsgType.STATUS, {"status": 1, "verifier_id": bytes(32), "device_id": bytes(32)})
                self.core.on_frame(peer, framing.fragment(big, msg_no, 20)[0])
            elif choice == 11:  # a pairing window opens or closes
                if self.core._pairing is None:
                    self.core.start_pairing(ACCOUNT, 120, lambda e: None)
                else:
                    self.core.cancel_pairing()
            elif choice == 12 and phone is not None:
                phone.hello(self.verifier.verifier_id if rng.random() < 0.7 else None)

            for req in requests:  # never more than one result per caller
                self.assertLessEqual(len(req.finals()), 1, req.events)

        self.core.cancel_pairing()
        # Time passes with the phones still connected but silent: every request
        # still ends within its TTL (the timeout alone must be enough).
        for phone in self.transport.phones:
            phone.auto_reply = False
        self.scheduler.fire_all()
        self.assertEqual({}, self.core._waiters, "request outlived its TTL on a live link")
        self.quiesce()
        self.assert_idle()
        for req in requests:  # every caller that kept waiting got exactly one answer
            expected = 0 if req.cancelled else 1
            self.assertEqual(expected, len(req.finals()), req.events)
        self.assert_works_again()


class RepeatedAttemptsTest(ResilienceTestCase):
    """Condition 19: many attempts in a row, in every outcome, leave nothing behind."""

    def test_two_hundred_attempts_in_mixed_outcomes(self):
        phone = self.connect(self.phone)
        outcomes = {"ok": 0, "denied": 0, "unavailable": 0}
        for i in range(200):
            mode = i % 4
            phone.approve = mode != 1
            phone.auto_reply = mode != 2
            events = []
            request_id = self.core.authenticate(ACCOUNT, "linux.sudo", "test-host", events.append)
            if mode == 2:
                self.core.cancel_auth(request_id)  # the caller gave up
                self.assertEqual(1, len(events))  # only "sent"
                phone.held.clear()
                continue
            if mode == 3 and i % 8 == 3:  # a timeout now and then
                phone.auto_reply = False
            final = events[-1]
            if "result" not in final:
                self.scheduler.fire_all()  # TTL passes
                final = events[-1]
                phone = self.connect(self.phone) if phone not in self.transport.phones else phone
            outcomes[final["result"]] += 1
        self.assertGreater(outcomes["ok"], 0)
        self.assertGreater(outcomes["denied"], 0)
        self.assertEqual({}, self.core._waiters)
        self.assertEqual(0, self.verifier.pending_count)
        phone = self.transport.phones[0] if self.transport.phones else self.connect(self.phone)
        phone.approve = phone.auto_reply = True
        last = []
        self.core.authenticate(ACCOUNT, "linux.sudo", "test-host", last.append)
        self.assertEqual({"result": "ok"}, last[-1])


class DaemonRestartTest(ResilienceTestCase):
    """Condition 12: a restarted daemon forgets in-flight requests and works at once."""

    def test_answer_for_a_request_from_before_the_restart_is_ignored(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        self.authenticate()
        stale_answer = phone.held[0]

        # The daemon restarts: same registry and key on disk, nothing in memory.
        restarted = Verifier(self.verifier._key, self.verifier.registry, display_name="test-host",
                             clock=self.clock, allow_software_keys=True)
        self.verifier = restarted
        self.core = DaemonCore(restarted, self.transport, self.scheduler)
        self.transport.phones.clear()
        self.scheduler.timers.clear()
        phone = FakePhone(self.core, phone.peer_id, self.phone)
        self.transport.phones.append(phone)
        self.core.on_connect(phone.peer_id, 185)
        phone.hello(restarted.verifier_id)

        events = []
        phone.auto_reply = False
        self.core.authenticate(ACCOUNT, "phonekey.test", "test-host", events.append)
        phone.send(stale_answer)  # the old answer arrives first
        self.assertEqual(["sent"], [e.get("event") for e in events])  # ignored, request still open
        phone.send(phone.held[-1])
        self.assertEqual({"result": "ok"}, events[-1])


if __name__ == "__main__":
    unittest.main()
