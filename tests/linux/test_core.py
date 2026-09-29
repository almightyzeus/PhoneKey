"""Daemon core over a fake BLE link: pairing, auth, disconnects, timeouts (SECURITY.md T-6, T-9, T-12)."""

import unittest

from phonekey import codec, framing
from phonekey.codec import ErrorCode, MsgType, Status
from phonekey.core import KEEPALIVE_INTERVAL, DaemonCore
from phonekey.simulator import SimulatedAuthenticator
from tests.helpers import ACCOUNT, VerifierTestCase


class FakeScheduler:
    def __init__(self):
        self.timers = {}
        self._next = 0

    def call_later(self, seconds, callback):
        self._next += 1
        self.timers[self._next] = (seconds, callback)
        return self._next

    def cancel(self, handle):
        self.timers.pop(handle, None)

    def fire_all(self):
        for handle, (_, callback) in list(self.timers.items()):
            del self.timers[handle]
            callback()


class FakePhone:
    """A simulated authenticator on the far side of the BLE link."""

    def __init__(self, core: DaemonCore, peer_id: str, auth: SimulatedAuthenticator, mtu: int = 185):
        self.core, self.peer_id, self.auth, self.mtu = core, peer_id, auth, mtu
        self.rx = framing.Reassembler()
        self.connected = True
        self.approve = True
        self.auto_reply = True
        self.keepalive = True
        self.received: list[codec.Message] = []
        self.held: list[bytes] = []  # replies withheld when auto_reply is off
        self._msg_no = 0

    def send(self, message: bytes) -> None:
        self._msg_no += 1
        for frame in framing.fragment(message, self._msg_no, framing.max_payload(self.mtu)):
            self.core.on_frame(self.peer_id, frame, self.mtu)

    def on_indication(self, frame: bytes) -> None:
        if not self.connected:
            return
        data = self.rx.feed(frame)
        if data is None:
            return
        msg = codec.decode(data)
        self.received.append(msg)
        reply = None
        if msg.type is MsgType.STATUS and msg["status"] == Status.READY and self.keepalive:
            self.hello(msg["verifier_id"])
            return
        if msg.type is MsgType.PAIR_REQUEST and self.auth._verifiers.get(msg["verifier_id"]) is None:
            reply = self.auth.handle_pair_request(data)
        elif msg.type is MsgType.AUTH_REQUEST:
            reply = self.auth.handle_auth_request(data, approve=self.approve)
        if reply is not None:
            if self.auto_reply:
                self.send(reply)
            else:
                self.held.append(reply)

    def hello(self, verifier_id=None) -> None:
        """STATUS READY after subscribing (with ids once paired)."""
        fields = {"status": Status.READY}
        if verifier_id is not None:
            fields.update(verifier_id=verifier_id, device_id=self.auth.device_id)
        self.send(codec.encode(MsgType.STATUS, fields))


class FakeTransport:
    def __init__(self):
        self.phones: list[FakePhone] = []
        self.pairing_mode = False
        self.frames = 0
        self.dropped = []

    def send(self, peer_id, frame):
        self.frames += 1
        for phone in list(self.phones):
            if phone.peer_id == peer_id:
                phone.on_indication(frame)

    def set_pairing_mode(self, enabled):
        self.pairing_mode = enabled

    def drop(self, peer_id):
        self.dropped.append(peer_id)


class CoreTestCase(VerifierTestCase):
    def setUp(self):
        super().setUp()  # verifier with self.phone (simulator) already paired for ACCOUNT
        self.transport = FakeTransport()
        self.scheduler = FakeScheduler()
        self.core = DaemonCore(self.verifier, self.transport, self.scheduler)
        self.events = []

    def connect(self, auth, peer_id="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01", hello=True, mtu=185):
        phone = FakePhone(self.core, peer_id, auth, mtu)
        self.transport.phones.append(phone)
        self.core.on_connect(peer_id, mtu)
        if hello:
            phone.hello(self.verifier.verifier_id)
        return phone

    def disconnect(self, phone):
        phone.connected = False
        self.transport.phones.remove(phone)
        self.core.on_disconnect(phone.peer_id)

    def authenticate(self, account=ACCOUNT):
        self.core.authenticate(account, "phonekey.test", "test-host", self.events.append)
        return self.events[-1]


class AuthOverLinkTest(CoreTestCase):
    def test_success_over_small_mtu(self):
        self.connect(self.phone, mtu=23)  # forces many fragments each way
        self.assertEqual({"result": "ok"}, self.authenticate())
        self.assertEqual({"event": "sent", "device": "Simulated phone"}, self.events[0])
        # Only the keepalive timer remains; the auth timeout was cancelled.
        self.assertEqual([KEEPALIVE_INTERVAL], [t for t, _ in self.scheduler.timers.values()])
        self.assertEqual(0, self.verifier.pending_count)

    def test_phone_not_connected(self):
        self.assertEqual("unavailable", self.authenticate()["result"])
        self.assertEqual(0, self.transport.frames)

    def test_hello_without_ids_does_not_count_as_connected(self):
        self.connect(self.phone, hello=False).hello()
        self.assertEqual("unavailable", self.authenticate()["result"])

    def test_unpaired_device_claim_is_ignored(self):
        stranger = SimulatedAuthenticator()
        self.connect(stranger)  # claims our verifier_id, but its device_id isn't registered
        self.assertEqual(set(), self.core.connected_device_ids())

    def test_other_account_has_no_phone(self):
        self.connect(self.phone)
        self.assertEqual("unavailable", self.authenticate(account="bob")["result"])

    def test_denied(self):
        self.connect(self.phone).approve = False
        self.assertEqual({"result": "denied", "reason": "USER_DENIED"}, self.authenticate())

    def test_timeout_fails_closed(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        self.assertEqual("sent", self.authenticate()["event"])
        self.scheduler.fire_all()
        self.assertEqual({"result": "unavailable", "reason": "timed out"}, self.events[-1])
        self.assertEqual([phone.peer_id], self.transport.dropped)  # reconnect for next time
        phone.send(phone.held[0])  # a late answer changes nothing
        self.assertEqual(2, len(self.events))

    def test_disconnect_mid_auth_fails_closed(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        self.authenticate()
        self.disconnect(phone)
        self.assertEqual({"result": "unavailable", "reason": "phone disconnected"}, self.events[-1])
        self.assertEqual({}, self.scheduler.timers)

    def test_caller_giving_up_withdraws_request(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        request_id = self.core.authenticate(ACCOUNT, "linux.unlock", "test-host", self.events.append)
        self.assertEqual("sent", self.events[-1]["event"])
        self.core.cancel_auth(request_id)
        told = phone.received[-1]
        self.assertEqual(MsgType.ERROR, told.type)  # phone dismisses its prompt
        self.assertEqual((ErrorCode.EXPIRED, request_id), (told["error_code"], told["request_id"]))
        self.assertEqual(1, len(self.events))  # no result to a caller that has gone
        phone.send(phone.held[0])  # approving the stale prompt changes nothing
        self.assertEqual(1, len(self.events))
        phone.auto_reply = True
        self.assertEqual({"result": "ok"}, self.authenticate())  # the device is free again, not BUSY

    def test_cancel_after_result_or_unknown_is_harmless(self):
        phone = self.connect(self.phone)
        request_id = self.core.authenticate(ACCOUNT, "phonekey.test", "test-host", self.events.append)
        self.assertEqual({"result": "ok"}, self.events[-1])
        before = len(phone.received)
        self.core.cancel_auth(request_id)
        self.core.cancel_auth(bytes(16))
        self.assertEqual(before, len(phone.received))

    def test_not_sent_returns_no_request_id(self):
        self.assertIsNone(self.core.authenticate(ACCOUNT, "phonekey.test", "test-host", self.events.append))

    def test_reconnect_then_success(self):
        phone = self.connect(self.phone)
        self.disconnect(phone)
        self.connect(self.phone, peer_id="/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02")
        self.assertEqual({"result": "ok"}, self.authenticate())

    def test_duplicate_request_while_pending_is_busy(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        self.authenticate()
        second = []
        self.core.authenticate(ACCOUNT, "phonekey.test", "test-host", second.append)
        self.assertEqual({"result": "unavailable", "reason": "BUSY"}, second[-1])

    def test_replayed_response_over_link_ignored(self):
        phone = self.connect(self.phone)
        phone.auto_reply = False
        self.authenticate()
        response = phone.held[0]
        phone.send(response)
        self.assertEqual({"result": "ok"}, self.events[-1])
        phone.send(response)
        self.assertEqual(2, len(self.events))  # no second result

    def test_request_goes_only_to_the_target_phone(self):
        other = SimulatedAuthenticator("Bob's phone")
        self.pair(other, account="bob")
        bob = self.connect(other, peer_id="/org/bluez/hci0/dev_BB")
        self.connect(self.phone)
        self.assertEqual({"result": "ok"}, self.authenticate())
        self.assertEqual([], other.prompts)
        self.assertEqual([], bob.received)

    def test_malformed_frames_get_error_and_do_not_break_link(self):
        phone = self.connect(self.phone)
        self.core.on_frame(phone.peer_id, b"\x05\x02\x00garbage")  # out-of-order frame
        self.assertEqual(MsgType.ERROR, phone.received[-1].type)
        phone.send(b"PK\x01\x05\x10\x00\x02\x00\x01")  # bad STATUS encoding
        self.assertEqual(ErrorCode.MALFORMED, phone.received[-1]["error_code"])
        self.assertEqual({"result": "ok"}, self.authenticate())


class PairingOverLinkTest(CoreTestCase):
    def start(self, window=120):
        self.core.start_pairing(ACCOUNT, window, self.events.append)

    def progress(self):
        return [e["message"] for e in self.events if e.get("event") == "progress"]

    def test_progress_tells_user_to_approve_on_phone(self):
        self.start()
        phone = self.connect(SimulatedAuthenticator("New phone"), hello=False)
        phone.hello()
        self.assertEqual(1, len(self.progress()))
        self.assertIn("approve this computer on your phone", self.progress()[0])
        self.assertEqual("paired", self.events[-1]["result"])

    def test_progress_explains_a_dropped_link_and_keeps_the_window_open(self):
        self.start()
        phone = self.connect(SimulatedAuthenticator("New phone"), hello=False)
        phone.auto_reply = False
        phone.hello()
        self.disconnect(phone)
        self.assertIn("reconnecting", self.progress()[-1])
        self.assertNotIn("result", self.events[-1])  # still waiting, not failed
        self.assertTrue(self.transport.pairing_mode)

    def test_progress_outside_pairing_is_ignored(self):
        self.core.pairing_progress("nobody is listening")
        self.assertEqual([], self.events)

    def test_pairing_flow(self):
        self.start()
        self.assertTrue(self.transport.pairing_mode)
        newcomer = SimulatedAuthenticator("New phone")
        phone = self.connect(newcomer, hello=False)
        phone.hello()  # no ids: a phone in pairing mode
        result = self.events[-1]
        self.assertEqual("paired", result["result"])
        self.assertEqual(newcomer.device_id.hex(), result["device_id"])
        self.assertFalse(self.transport.pairing_mode)
        self.assertEqual(Status.PAIRED, phone.received[-1]["status"])
        self.assertEqual("DD:EE:01", self.verifier.registry.get(newcomer.device_id).bond_address[-8:])
        self.assertIn(newcomer.device_id, self.core.connected_device_ids())

    def test_no_pair_request_outside_window(self):
        phone = self.connect(SimulatedAuthenticator(), hello=False)
        phone.hello()
        self.assertEqual([], phone.received)

    def test_window_expires(self):
        self.start()
        self.scheduler.fire_all()
        self.assertEqual({"result": "error", "reason": "EXPIRED"}, self.events[-1])
        self.assertFalse(self.transport.pairing_mode)
        phone = self.connect(SimulatedAuthenticator(), hello=False)
        phone.hello()
        self.assertEqual([], phone.received)

    def test_cancel(self):
        self.start()
        self.core.cancel_pairing()
        self.assertEqual({"result": "cancelled"}, self.events[-1])
        self.assertFalse(self.transport.pairing_mode)

    def test_second_pairing_refused_while_open(self):
        self.start()
        other = []
        self.core.start_pairing(ACCOUNT, 120, other.append)
        self.assertEqual("error", other[-1]["result"])

    def test_software_key_refused_by_strict_verifier(self):
        strict = self.make_verifier(allow_software_keys=False)
        core = DaemonCore(strict, self.transport, self.scheduler)
        core.start_pairing(ACCOUNT, 120, self.events.append)
        phone = FakePhone(core, "/dev_X", SimulatedAuthenticator())
        self.transport.phones.append(phone)
        core.on_connect(phone.peer_id)
        phone.hello()
        self.assertEqual({"result": "error", "reason": "INSECURE_KEY"}, self.events[-1])
        self.assertFalse(self.transport.pairing_mode)

    def test_bond_confirmation_outside_pairing_is_rejected(self):
        answers = []
        self.core.on_bond_confirmation("/dev_X", 123456, answers.append)
        self.assertEqual([False], answers)

    def test_bond_confirmation_is_forwarded_and_answered(self):
        self.start()
        answers = []
        self.core.on_bond_confirmation("/dev_X", 42, answers.append)
        self.assertEqual({"event": "confirm", "passkey": "000042"}, self.events[-1])
        self.core.answer_bond_confirmation(True)
        self.assertEqual([True], answers)
        self.core.answer_bond_confirmation(True)  # no double answer
        self.assertEqual([True], answers)

    def test_unanswered_confirmation_is_rejected_when_window_ends(self):
        self.start()
        answers = []
        self.core.on_bond_confirmation("/dev_X", 1, answers.append)
        self.core.cancel_pairing()
        self.assertEqual([False], answers)

    def test_silent_phone_after_subscribing_is_dropped(self):
        phone = self.connect(self.phone, hello=False)
        self.scheduler.fire_all()
        self.assertEqual([phone.peer_id], self.transport.dropped)

    def test_greeting_phone_is_kept(self):
        self.connect(self.phone)
        self.scheduler.fire_all()
        self.assertEqual([], self.transport.dropped)

    def test_keepalive_is_answered(self):
        self.connect(self.phone)
        self.scheduler.fire_all()  # ping
        self.scheduler.fire_all()  # its answer window, then the next ping
        self.assertEqual([], self.transport.dropped)

    def test_phone_that_stops_answering_keepalive_is_dropped(self):
        phone = self.connect(self.phone)
        phone.keepalive = False  # e.g. the app restarted while the link stayed up
        self.scheduler.fire_all()  # ping
        self.scheduler.fire_all()  # no answer
        self.assertEqual([phone.peer_id], self.transport.dropped)

    def test_status_reports_devices(self):
        self.connect(self.phone)
        status = self.core.status()
        self.assertEqual(1, len(status["paired"]))
        self.assertTrue(status["paired"][0]["connected"])
        self.assertFalse(status["pairing"])


if __name__ == "__main__":
    unittest.main()
