#!/usr/bin/env python3
"""Regenerates protocol/test-vectors/v1.json from the reference Python implementation.

Keys are generated fresh and discarded: the file contains only public keys,
messages and signatures, never private keys. ECDSA signatures are randomized,
so each run produces different bytes; commit the output, don't regenerate casually.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "linux" / "daemon"))

from phonekey import codec, crypto  # noqa: E402
from phonekey.codec import FIELDS_BY_NAME, Kind, MsgType  # noqa: E402
from phonekey.simulator import SimulatedAuthenticator, error  # noqa: E402
from phonekey.verifier import Verifier  # noqa: E402
from phonekey.registry import Registry  # noqa: E402

LABELS = {
    "pair-request": crypto.LABEL_PAIR_REQUEST,
    "pair-response": crypto.LABEL_PAIR_RESPONSE,
    "auth-request": crypto.LABEL_AUTH_REQUEST,
    "auth-assertion": crypto.LABEL_AUTH_ASSERTION,
}
LABEL_FOR_TYPE = {
    MsgType.PAIR_REQUEST: "pair-request",
    MsgType.PAIR_RESPONSE: "pair-response",
    MsgType.AUTH_REQUEST: "auth-request",
    MsgType.AUTH_RESPONSE: "auth-assertion",
}


def json_fields(msg: codec.Message) -> dict:
    """Bytes fields as lowercase hex, strings as strings, integers as numbers."""
    return {
        name: value.hex() if FIELDS_BY_NAME[name].kind is Kind.BYTES else value
        for name, value in msg.fields.items()
    }


def valid_vector(name: str, data: bytes, signer_spki: bytes | None) -> dict:
    msg = codec.decode(data)
    vector = {"name": name, "type": msg.type.name, "hex": data.hex(), "fields": json_fields(msg)}
    if signer_spki is not None:
        vector["signature"] = {
            "label": LABEL_FOR_TYPE[msg.type],
            "signed_hex": msg.signed_part.hex(),
            "public_key": signer_spki.hex(),
        }
    return vector


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + len(value).to_bytes(2, "big") + value


def main() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        verifier = Verifier(crypto.generate_key(), Registry(Path(tmp)), display_name="test-verifier",
                            allow_software_keys=True)
        phone = SimulatedAuthenticator("Test phone")
        pair_request = verifier.begin_pairing(account="alice")
        pair_response = phone.handle_pair_request(pair_request)
        verifier.complete_pairing(pair_response)
        _, auth_request = verifier.begin_auth(phone.device_id, account="alice", action="linux.sudo",
                                              resource="test-host")
        auth_response = phone.handle_auth_request(auth_request)
        assert verifier.complete_auth(auth_response).ok
        _, auth_request_detail = verifier.begin_auth(phone.device_id, account="alice", action="linux.sudo",
                                                     resource="test-host", detail="sudo apt upgrade 'a b' é")

    status = codec.encode(MsgType.STATUS, {"status": codec.Status.READY})
    err = error(codec.ErrorCode.USER_DENIED, bytes(16))

    valid = [
        valid_vector("pair_request", pair_request, verifier.spki),
        valid_vector("pair_response", pair_response, phone.spki),
        valid_vector("auth_request", auth_request, verifier.spki),
        valid_vector("auth_response", auth_response, phone.spki),
        valid_vector("auth_request_with_detail", auth_request_detail, verifier.spki),
        valid_vector("status", status, None),
        valid_vector("error", err, None),
    ]

    # Signature checks that must FAIL, derived from the valid auth_response.
    resp = codec.decode(auth_response)
    sig = resp["signature"]
    bad_sig = bytearray(sig)
    bad_sig[-1] ^= 1
    signatures_invalid = [
        {"name": "flipped signature byte", "label": "auth-assertion", "signed_hex": resp.signed_part.hex(),
         "signature_hex": bytes(bad_sig).hex(), "public_key": phone.spki.hex()},
        {"name": "flipped message byte", "label": "auth-assertion",
         "signed_hex": (resp.signed_part[:-1] + bytes([resp.signed_part[-1] ^ 1])).hex(),
         "signature_hex": sig.hex(), "public_key": phone.spki.hex()},
        {"name": "wrong label", "label": "auth-request", "signed_hex": resp.signed_part.hex(),
         "signature_hex": sig.hex(), "public_key": phone.spki.hex()},
        {"name": "wrong key", "label": "auth-assertion", "signed_hex": resp.signed_part.hex(),
         "signature_hex": sig.hex(), "public_key": verifier.spki.hex()},
    ]

    header = b"PK\x01\x05"
    ready = tlv(0x10, b"\x01")
    invalid = [
        ("empty", b"", "MALFORMED"),
        ("bad magic", b"PX\x01\x05" + ready, "MALFORMED"),
        ("unsupported version", b"PK\x02\x05" + ready, "UNSUPPORTED_VERSION"),
        ("unknown type", b"PK\x01\x09" + ready, "MALFORMED"),
        ("missing required field", header, "MALFORMED"),
        ("tags out of order", header + tlv(0x10, b"\x01") + tlv(0x03, bytes(16)), "MALFORMED"),
        ("repeated tag", header + ready + ready, "MALFORMED"),
        ("unknown tag", header + ready + tlv(0x14, b"x"), "MALFORMED"),
        ("detail not allowed for type", header + ready + tlv(0x13, b"x"), "MALFORMED"),
        ("tag not allowed for type", header + tlv(0x04, bytes(32)) + ready, "MALFORMED"),
        ("wrong fixed length", header + tlv(0x03, bytes(15)) + ready, "MALFORMED"),
        ("wrong integer width", header + tlv(0x10, b"\x00\x01"), "MALFORMED"),
        ("length overruns message", header + b"\x10\x00\x05\x01", "MALFORMED"),
        ("truncated field header", header + ready + b"\x11\x00", "MALFORMED"),
        ("trailing byte", header + ready + b"\x00", "MALFORMED"),
        ("invalid utf-8", b"PK\x01\x06" + tlv(0x11, b"\x00\x01") + tlv(0x12, b"\xff"), "MALFORMED"),
        ("control character", b"PK\x01\x06" + tlv(0x11, b"\x00\x01") + tlv(0x12, b"a\nb"), "MALFORMED"),
        ("bidi override", b"PK\x01\x06" + tlv(0x11, b"\x00\x01") + tlv(0x12, "a‮b".encode()), "MALFORMED"),
        ("oversized message", header + ready + tlv(0x12, bytes(codec.MAX_MESSAGE_SIZE)), "MALFORMED"),
    ]

    out = {
        "description": "PhoneKey protocol v1 test vectors. See protocol/PROTOCOL.md §3. "
                       "Bytes fields are hex; decoding 'hex' must give 'fields', and encoding "
                       "'fields' must give exactly 'hex'.",
        "labels": {k: v.decode("ascii").replace("\0", "\\0") for k, v in LABELS.items()},
        "valid": valid,
        "signatures_invalid": signatures_invalid,
        "invalid": [{"name": n, "hex": d.hex(), "error": e} for n, d, e in invalid],
    }
    path = ROOT / "protocol" / "test-vectors" / "v1.json"
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    os.umask(0o077)
    main()
