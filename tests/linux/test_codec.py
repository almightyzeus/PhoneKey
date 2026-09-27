"""Codec conformance: shared test vectors plus rule-by-rule checks (PROTOCOL.md §3)."""

import json
import unittest

from phonekey import codec, crypto
from phonekey.codec import FIELDS_BY_NAME, ErrorCode, Kind, MsgType, ProtocolError
from tests.helpers import ROOT

VECTORS = json.loads((ROOT / "protocol" / "test-vectors" / "v1.json").read_text())
LABELS = {
    "pair-request": crypto.LABEL_PAIR_REQUEST,
    "pair-response": crypto.LABEL_PAIR_RESPONSE,
    "auth-request": crypto.LABEL_AUTH_REQUEST,
    "auth-assertion": crypto.LABEL_AUTH_ASSERTION,
}


def from_json(fields: dict) -> dict:
    return {
        name: bytes.fromhex(value) if FIELDS_BY_NAME[name].kind is Kind.BYTES else value
        for name, value in fields.items()
    }


class VectorTest(unittest.TestCase):
    def test_valid_vectors_decode_to_expected_fields(self):
        for v in VECTORS["valid"]:
            with self.subTest(v["name"]):
                msg = codec.decode(bytes.fromhex(v["hex"]))
                self.assertEqual(MsgType[v["type"]], msg.type)
                self.assertEqual(from_json(v["fields"]), dict(msg.fields))

    def test_valid_vectors_encode_to_exact_bytes(self):
        for v in VECTORS["valid"]:
            with self.subTest(v["name"]):
                encoded = codec.encode(MsgType[v["type"]], from_json(v["fields"]))
                self.assertEqual(v["hex"], encoded.hex())

    def test_vector_signatures_verify(self):
        for v in VECTORS["valid"]:
            if "signature" not in v:
                continue
            with self.subTest(v["name"]):
                s = v["signature"]
                msg = codec.decode(bytes.fromhex(v["hex"]))
                self.assertEqual(s["signed_hex"], msg.signed_part.hex())
                key = crypto.load_public_key(bytes.fromhex(s["public_key"]))
                self.assertTrue(crypto.verify(key, LABELS[s["label"]], msg.signed_part, msg["signature"]))

    def test_invalid_signature_vectors_fail(self):
        for v in VECTORS["signatures_invalid"]:
            with self.subTest(v["name"]):
                key = crypto.load_public_key(bytes.fromhex(v["public_key"]))
                self.assertFalse(crypto.verify(key, LABELS[v["label"]], bytes.fromhex(v["signed_hex"]),
                                               bytes.fromhex(v["signature_hex"])))

    def test_invalid_vectors_rejected_with_expected_error(self):
        for v in VECTORS["invalid"]:
            with self.subTest(v["name"]):
                with self.assertRaises(ProtocolError) as ctx:
                    codec.decode(bytes.fromhex(v["hex"]))
                self.assertEqual(ErrorCode[v["error"]], ctx.exception.code)


class EncodeRulesTest(unittest.TestCase):
    def test_encode_refuses_what_decode_would_reject(self):
        cases = [
            (MsgType.STATUS, {}),                                         # missing required
            (MsgType.STATUS, {"status": 1, "challenge": bytes(32)}),      # not allowed for type
            (MsgType.STATUS, {"status": 256}),                            # integer out of range
            (MsgType.STATUS, {"status": 1, "request_id": bytes(15)}),     # wrong fixed size
            (MsgType.ERROR, {"error_code": 1, "error_detail": "x" * 129}),  # too long
            (MsgType.ERROR, {"error_code": 1, "error_detail": "a⁦b"}),  # bidi isolate
        ]
        for mtype, fields in cases:
            with self.subTest(fields=fields):
                with self.assertRaises(ProtocolError):
                    codec.encode(mtype, fields)

    def test_encode_rejects_wrong_python_types(self):
        with self.assertRaises(TypeError):
            codec.encode(MsgType.STATUS, {"status": True})
        with self.assertRaises(TypeError):
            codec.encode(MsgType.ERROR, {"error_code": 1, "error_detail": b"bytes"})

    def test_fields_are_emitted_in_tag_order(self):
        data = codec.encode(MsgType.ERROR, {"error_detail": "x", "request_id": bytes(16), "error_code": 7})
        self.assertEqual([0x03, 0x11, 0x12], [data[4], data[4 + 3 + 16], data[4 + 3 + 16 + 3 + 2]])

    def test_signed_part_is_everything_before_signature(self):
        unsigned = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
            "verifier_id": bytes(32), "device_id": bytes(32), "request_id": bytes(16), "request_hash": bytes(32),
        })
        msg = codec.decode(codec.with_signature(unsigned, bytes(70)))
        self.assertEqual(unsigned, msg.signed_part)

    def test_signed_type_without_signature_is_rejected(self):
        unsigned = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
            "verifier_id": bytes(32), "device_id": bytes(32), "request_id": bytes(16), "request_hash": bytes(32),
        })
        with self.assertRaises(ProtocolError):
            codec.decode(unsigned)

    def test_unsigned_encoding_only_for_signed_types(self):
        with self.assertRaises(ValueError):
            codec.encode_unsigned(MsgType.STATUS, {"status": 1})

    def test_signature_length_limits(self):
        base = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
            "verifier_id": bytes(32), "device_id": bytes(32), "request_id": bytes(16), "request_hash": bytes(32),
        })
        for bad in (bytes(7), bytes(73)):
            with self.assertRaises(ProtocolError):
                codec.with_signature(base, bad)

    def test_empty_optional_string_allowed_but_empty_required_string_rejected(self):
        codec.decode(codec.encode(MsgType.ERROR, {"error_code": 1, "error_detail": ""}))
        with self.assertRaises(ProtocolError):
            codec.encode_unsigned(MsgType.AUTH_REQUEST, {
                "verifier_id": bytes(32), "device_id": bytes(32), "request_id": bytes(16),
                "challenge": bytes(32), "action": "", "resource": "h", "account": "a",
                "issued_at": 0, "ttl_ms": 0,
            })


if __name__ == "__main__":
    unittest.main()
