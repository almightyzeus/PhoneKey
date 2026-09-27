"""Application-level pairing (PROTOCOL.md §5.2; SECURITY.md T-11, D-3, D-5)."""

import unittest

from phonekey import codec, crypto
from phonekey.codec import ErrorCode, KeySecurity, MsgType, ProtocolError
from phonekey.simulator import SimulatedAuthenticator, error
from tests.helpers import ACCOUNT, VerifierTestCase
from tests.linux.test_verifier import resign


class PairingTest(VerifierTestCase):
    def setUp(self):
        super().setUp()
        self.new_phone = SimulatedAuthenticator("New phone")

    def assert_pairing_fails(self, response: bytes, code: ErrorCode):
        with self.assertRaises(ProtocolError) as ctx:
            self.verifier.complete_pairing(response)
        self.assertEqual(code, ctx.exception.code)
        self.assertIsNone(self.verifier.registry.get(self.new_phone.device_id))

    def test_valid_pairing_registers_device(self):
        record = self.pair(self.new_phone)
        self.assertEqual(self.new_phone.device_id, record.device_id)
        self.assertEqual(crypto.key_id(record.public_key), record.device_id)
        self.assertEqual(ACCOUNT, record.account)
        self.assertEqual("New phone", record.display_name)
        self.assertEqual(record, self.verifier.registry.get(self.new_phone.device_id))

    def test_pair_request_is_signed_by_verifier(self):
        msg = codec.decode(self.verifier.begin_pairing(account=ACCOUNT))
        key = crypto.load_public_key(msg["public_key"])
        self.assertEqual(self.verifier.verifier_id, msg["verifier_id"])
        self.assertTrue(crypto.verify(key, crypto.LABEL_PAIR_REQUEST, msg.signed_part, msg["signature"]))

    def test_software_key_refused_by_default(self):
        strict = self.make_verifier(allow_software_keys=False)
        response = self.new_phone.handle_pair_request(strict.begin_pairing(account=ACCOUNT))
        with self.assertRaises(ProtocolError) as ctx:
            strict.complete_pairing(response)
        self.assertEqual(ErrorCode.INSECURE_KEY, ctx.exception.code)

    def test_hardware_key_accepted_by_strict_verifier(self):
        strict = self.make_verifier(allow_software_keys=False)
        response = self.new_phone.handle_pair_request(strict.begin_pairing(account=ACCOUNT))
        # Simulate a TEE-backed key report (re-signed by the phone's own key).
        response = resign(response, self.new_phone._key, crypto.LABEL_PAIR_RESPONSE, key_security=KeySecurity.TEE)
        self.assertEqual(KeySecurity.TEE, strict.complete_pairing(response).key_security)

    def test_no_pairing_window(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        self.verifier.complete_pairing(response)
        with self.assertRaises(ProtocolError) as ctx:  # session is one-shot
            self.verifier.complete_pairing(response)
        self.assertEqual(ErrorCode.NOT_PAIRING, ctx.exception.code)

    def test_response_without_any_window(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        fresh = self.make_verifier()  # e.g. after a restart: no window open
        with self.assertRaises(ProtocolError) as ctx:
            fresh.complete_pairing(response)
        self.assertEqual(ErrorCode.NOT_PAIRING, ctx.exception.code)

    def test_failed_attempt_closes_window(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        bad = bytearray(response)
        bad[-1] ^= 1
        self.assert_pairing_fails(bytes(bad), ErrorCode.BAD_SIGNATURE)
        self.assert_pairing_fails(response, ErrorCode.NOT_PAIRING)

    def test_expired_window(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT, window=10))
        self.clock.now += 10.001
        self.assert_pairing_fails(response, ErrorCode.EXPIRED)

    def test_wrong_nonce(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        forged = resign(response, self.new_phone._key, crypto.LABEL_PAIR_RESPONSE, pairing_nonce=bytes(32))
        self.assert_pairing_fails(forged, ErrorCode.BAD_SIGNATURE)

    def test_response_to_older_request(self):
        old = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        self.verifier.begin_pairing(account=ACCOUNT)  # a new window replaces the old one
        self.assert_pairing_fails(old, ErrorCode.BAD_SIGNATURE)

    def test_device_id_must_match_public_key(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        forged = resign(response, self.new_phone._key, crypto.LABEL_PAIR_RESPONSE, device_id=bytes(32))
        self.assert_pairing_fails(forged, ErrorCode.MALFORMED)

    def test_proof_of_possession_required(self):
        # Attacker submits the victim phone's public key but cannot sign with it.
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        forged = resign(response, crypto.generate_key(), crypto.LABEL_PAIR_RESPONSE)
        self.assert_pairing_fails(forged, ErrorCode.BAD_SIGNATURE)

    def test_non_p256_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        p384 = crypto.spki_of(ec.generate_private_key(ec.SECP384R1()).public_key())
        with self.assertRaises(ValueError):
            crypto.load_public_key(p384)
        # P-384 SPKI is 120 bytes, so the codec itself rejects it in PAIR_RESPONSE.
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        msg = codec.decode(response)
        with self.assertRaises(ProtocolError):
            codec.encode_unsigned(MsgType.PAIR_RESPONSE, {**{k: v for k, v in msg.fields.items() if k != "signature"},
                                                          "public_key": p384})

    def test_unknown_key_security_rejected(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        forged = resign(response, self.new_phone._key, crypto.LABEL_PAIR_RESPONSE, key_security=9)
        self.assert_pairing_fails(forged, ErrorCode.MALFORMED)

    def test_authenticator_refusal(self):
        self.verifier.begin_pairing(account=ACCOUNT)
        self.assert_pairing_fails(error(ErrorCode.USER_DENIED), ErrorCode.USER_DENIED)

    def test_wrong_label_on_pair_response(self):
        response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
        forged = resign(response, self.new_phone._key, crypto.LABEL_AUTH_ASSERTION)
        self.assert_pairing_fails(forged, ErrorCode.BAD_SIGNATURE)

    def test_attestation_is_informational(self):
        cases = {
            b"": "not provided",
            b"\x00\x03abc": "unparsable (ValueError)",
            b"\x00\xffabc": "unparsable (ValueError)",  # garbage chain must not block pairing
        }
        for chain, summary in cases.items():
            with self.subTest(chain=chain):
                self.verifier.registry.remove(self.new_phone.device_id)
                response = self.new_phone.handle_pair_request(self.verifier.begin_pairing(account=ACCOUNT))
                forged = resign(response, self.new_phone._key, crypto.LABEL_PAIR_RESPONSE, attestation_chain=chain)
                self.assertEqual(summary, self.verifier.complete_pairing(forged).attestation)

    def test_phone_rejects_pair_request_with_bad_verifier_signature(self):
        request = bytearray(self.verifier.begin_pairing(account=ACCOUNT))
        request[-1] ^= 1
        with self.assertRaises(ProtocolError):
            self.new_phone.handle_pair_request(bytes(request))


if __name__ == "__main__":
    unittest.main()
