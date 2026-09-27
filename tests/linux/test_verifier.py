"""Authentication checks on the verifier (PROTOCOL.md §8.1; SECURITY.md T-1..T-8, T-13)."""

import unittest

from phonekey import codec, crypto
from phonekey.codec import ErrorCode, MsgType, ProtocolError
from phonekey.simulator import SimulatedAuthenticator, error
from tests.helpers import ACCOUNT, VerifierTestCase


def resign(data: bytes, key: crypto.PrivateKey, label: bytes, **changes) -> bytes:
    """Re-encodes a signed message with changed fields and a fresh signature by `key`."""
    msg = codec.decode(data)
    fields = {k: v for k, v in msg.fields.items() if k != "signature"}
    fields.update(changes)
    unsigned = codec.encode_unsigned(msg.type, fields)
    return codec.with_signature(unsigned, crypto.sign(key, label, unsigned))


class AuthenticationTest(VerifierTestCase):
    def test_valid_assertion_accepted(self):
        request_id, request = self.request()
        result = self.verifier.complete_auth(self.phone.handle_auth_request(request))
        self.assertTrue(result.ok)
        self.assertEqual(self.phone.device_id, result.device_id)
        self.assertEqual(request_id, result.request_id)

    def test_request_shows_action_resource_and_account(self):
        _, request = self.request(action="linux.sudo")
        self.phone.handle_auth_request(request)
        self.assertEqual({"action": "linux.sudo", "resource": "test-host", "account": ACCOUNT},
                         self.phone.prompts[-1])

    def test_request_shows_command_detail(self):
        _, request = self.request(action="linux.sudo", detail="sudo apt upgrade")
        self.assertTrue(self.verifier.complete_auth(self.phone.handle_auth_request(request)).ok)
        self.assertEqual("sudo apt upgrade", self.phone.prompts[-1]["detail"])

    def test_detail_is_optional(self):
        _, request = self.request(action="linux.sudo")
        self.assertNotIn("detail", codec.decode(request).fields)

    # T-2: an attacker on the link cannot change or remove the command shown
    def test_modified_or_stripped_detail_refused_by_phone(self):
        _, request = self.request(action="linux.sudo", detail="sudo apt upgrade")
        msg = codec.decode(request)
        for fields in ({**msg.fields, "detail": "sudo true"},
                       {k: v for k, v in msg.fields.items() if k != "detail"}):
            with self.subTest(detail=fields.get("detail")):
                reply = self.phone.handle_auth_request(codec.encode(MsgType.AUTH_REQUEST, fields))
                self.assertEqual(ErrorCode.BAD_SIGNATURE, codec.decode(reply)["error_code"])

    def test_phone_signing_other_detail_rejected(self):
        _, request = self.request(action="linux.sudo", detail="sudo apt upgrade")
        msg = codec.decode(request)
        shown = codec.encode(MsgType.AUTH_REQUEST, {**msg.fields, "detail": "sudo true"})
        response = self._sign_response_for(shown, msg["request_id"])
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(response).error)

    def test_challenges_are_fresh(self):
        seen = set()
        for _ in range(50):
            request_id, request = self.request()
            msg = codec.decode(request)
            seen.add(msg["challenge"])
            self.verifier.cancel(request_id)
        self.assertEqual(50, len(seen))

    # T-1 replay
    def test_replayed_assertion_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.assertTrue(self.verifier.complete_auth(response).ok)
        self.assertEqual(ErrorCode.UNKNOWN_REQUEST, self.verifier.complete_auth(response).error)

    def test_assertion_for_other_request_rejected(self):
        _, first = self.request()
        old_response = self.phone.handle_auth_request(first)
        self.assertTrue(self.verifier.complete_auth(old_response).ok)
        # Same device, new request: the old assertion names the old request_id.
        _, second = self.request()
        self.assertFalse(self.verifier.complete_auth(old_response).ok)
        self.assertTrue(self.verifier.complete_auth(self.phone.handle_auth_request(second)).ok)

    def test_assertion_with_swapped_request_id_rejected(self):
        # Attacker relabels an assertion for request A as an answer to request B.
        _, request_a = self.request()
        response_a = self.phone.handle_auth_request(request_a)
        self.verifier.cancel(codec.decode(request_a)["request_id"])
        request_id_b, _ = self.request()
        msg = codec.decode(response_a)
        forged = codec.encode(MsgType.AUTH_RESPONSE, {**msg.fields, "request_id": request_id_b})
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(forged).error)

    def test_pending_requests_do_not_survive_restart(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        restarted = self.make_verifier()
        self.assertEqual(ErrorCode.UNKNOWN_REQUEST, restarted.complete_auth(response).error)

    # T-2 tampering
    def test_modified_challenge_rejected(self):
        _, request = self.request()
        msg = codec.decode(request)
        tampered = codec.encode(MsgType.AUTH_REQUEST, {**msg.fields, "challenge": bytes(32)})
        # The phone refuses: the verifier's signature no longer matches.
        reply = self.phone.handle_auth_request(tampered)
        self.assertEqual(MsgType.ERROR, codec.decode(reply).type)
        self.assertFalse(self.verifier.complete_auth(reply).ok)

    def test_modified_action_signed_by_phone_rejected(self):
        # Even if the phone signed a different request, the request_hash won't match.
        _, request = self.request(action="phonekey.test")
        msg = codec.decode(request)
        altered = codec.encode(MsgType.AUTH_REQUEST, {**msg.fields, "action": "linux.login"})
        response = self._sign_response_for(altered, msg["request_id"])
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(response).error)

    def _sign_response_for(self, request: bytes, request_id: bytes) -> bytes:
        unsigned = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
            "verifier_id": self.verifier.verifier_id, "device_id": self.phone.device_id,
            "request_id": request_id, "request_hash": crypto.sha256(request),
        })
        return codec.with_signature(unsigned, crypto.sign(self.phone._key, crypto.LABEL_AUTH_ASSERTION, unsigned))

    def test_modified_signature_rejected(self):
        _, request = self.request()
        response = bytearray(self.phone.handle_auth_request(request))
        response[-1] ^= 0x01
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(bytes(response)).error)

    def test_modified_request_hash_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        forged = resign(response, self.phone._key, crypto.LABEL_AUTH_ASSERTION, request_hash=bytes(32))
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(forged).error)

    # T-4 unknown phone
    def test_unregistered_key_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        stranger = crypto.generate_key()
        forged = resign(response, stranger, crypto.LABEL_AUTH_ASSERTION)  # claims the paired device_id
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(forged).error)

    def test_request_for_unpaired_device_refused(self):
        stranger = SimulatedAuthenticator()
        with self.assertRaises(ProtocolError) as ctx:
            self.request(device_id=stranger.device_id)
        self.assertEqual(ErrorCode.UNKNOWN_DEVICE, ctx.exception.code)

    def test_account_mismatch_refused(self):
        with self.assertRaises(ProtocolError) as ctx:
            self.request(account="bob")
        self.assertEqual(ErrorCode.UNKNOWN_DEVICE, ctx.exception.code)

    def test_response_from_other_devices_key_for_this_device_rejected(self):
        bob_phone = SimulatedAuthenticator()
        self.pair(bob_phone, account="bob")
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        forged = resign(response, bob_phone._key, crypto.LABEL_AUTH_ASSERTION)
        self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(forged).error)

    def test_response_naming_another_device_rejected(self):
        bob_phone = SimulatedAuthenticator()
        self.pair(bob_phone, account="bob")
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        forged = resign(response, bob_phone._key, crypto.LABEL_AUTH_ASSERTION, device_id=bob_phone.device_id)
        self.assertEqual(ErrorCode.UNKNOWN_DEVICE, self.verifier.complete_auth(forged).error)

    # T-6 spoofed verifier
    def test_phone_ignores_requests_from_unknown_verifier(self):
        impostor = self.make_verifier()  # different key, same registry and display name
        _, request = impostor.begin_auth(self.phone.device_id, account=ACCOUNT, action="linux.sudo",
                                         resource="test-host")
        reply = codec.decode(self.phone.handle_auth_request(request))
        self.assertEqual(ErrorCode.UNKNOWN_VERIFIER, reply["error_code"])
        self.assertEqual([], self.phone.prompts)

    # T-8 revocation
    def test_unpaired_device_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.verifier.registry.remove(self.phone.device_id)
        self.assertEqual(ErrorCode.UNKNOWN_DEVICE, self.verifier.complete_auth(response).error)

    def test_device_moved_to_other_account_mid_request_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        record = self.verifier.registry.get(self.phone.device_id)
        self.verifier.registry.add(type(record)(**{**record.__dict__, "account": "bob"}))
        self.assertEqual(ErrorCode.UNKNOWN_DEVICE, self.verifier.complete_auth(response).error)

    def test_response_naming_another_verifier_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        forged = resign(response, self.phone._key, crypto.LABEL_AUTH_ASSERTION, verifier_id=bytes(32))
        self.assertEqual(ErrorCode.UNKNOWN_VERIFIER, self.verifier.complete_auth(forged).error)

    # T-13 labels / versions
    def test_wrong_label_rejected(self):
        for label in (crypto.LABEL_AUTH_REQUEST, crypto.LABEL_PAIR_RESPONSE, b""):
            with self.subTest(label=label):
                _, request = self.request()
                response = self.phone.handle_auth_request(request)
                forged = resign(response, self.phone._key, label)
                self.assertEqual(ErrorCode.BAD_SIGNATURE, self.verifier.complete_auth(forged).error)

    def test_unknown_version_rejected(self):
        _, request = self.request()
        response = bytearray(self.phone.handle_auth_request(request))
        response[2] = 2
        self.assertEqual(ErrorCode.UNSUPPORTED_VERSION, self.verifier.complete_auth(bytes(response)).error)

    # Timeouts, errors, concurrency
    def test_expired_response_rejected(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.clock.now += self.verifier.auth_ttl + 0.001
        self.assertEqual(ErrorCode.EXPIRED, self.verifier.complete_auth(response).error)
        self.assertEqual(ErrorCode.UNKNOWN_REQUEST, self.verifier.complete_auth(response).error)

    def test_response_just_before_deadline_accepted(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.clock.now += self.verifier.auth_ttl - 0.001
        self.assertTrue(self.verifier.complete_auth(response).ok)

    def test_busy_when_request_pending(self):
        self.request()
        with self.assertRaises(ProtocolError) as ctx:
            self.request()
        self.assertEqual(ErrorCode.BUSY, ctx.exception.code)

    def test_expired_request_frees_device(self):
        self.request()
        self.clock.now += self.verifier.auth_ttl + 1
        self.request()  # no BUSY

    def test_cancel_after_disconnect_fails_closed(self):
        request_id, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.verifier.cancel(request_id)  # e.g. BLE link dropped
        self.assertEqual(ErrorCode.UNKNOWN_REQUEST, self.verifier.complete_auth(response).error)

    def test_error_reply_consumes_request(self):
        _, request = self.request()
        reply = self.phone.handle_auth_request(request, approve=False)
        self.assertEqual(ErrorCode.USER_DENIED, self.verifier.complete_auth(reply).error)
        self.assertEqual(0, self.verifier.pending_count)

    def test_unknown_peer_error_code_maps_to_internal(self):
        request_id, _ = self.request()
        reply = codec.encode(MsgType.ERROR, {"error_code": 0xBEEF, "request_id": request_id})
        self.assertEqual(ErrorCode.INTERNAL, self.verifier.complete_auth(reply).error)

    def test_unexpected_message_types_rejected(self):
        self.request()
        for data in (codec.encode(MsgType.STATUS, {"status": 1}), self.verifier.begin_pairing(account=ACCOUNT)):
            with self.subTest(type=codec.decode(data).type.name):
                self.assertEqual(ErrorCode.MALFORMED, self.verifier.complete_auth(data).error)

    def test_malformed_response_does_not_consume_request(self):
        _, request = self.request()
        response = self.phone.handle_auth_request(request)
        self.assertEqual(ErrorCode.MALFORMED, self.verifier.complete_auth(response[:-1]).error)
        self.assertTrue(self.verifier.complete_auth(response).ok)

    def test_error_helper_roundtrip(self):
        self.assertEqual(ErrorCode.BUSY, codec.decode(error(ErrorCode.BUSY))["error_code"])


if __name__ == "__main__":
    unittest.main()
