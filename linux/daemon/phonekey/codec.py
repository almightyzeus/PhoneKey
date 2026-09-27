"""PhoneKey v1 message encoding (protocol/PROTOCOL.md §3–§4).

Strict and deterministic: one message has exactly one valid encoding, and every
rule violation raises ProtocolError. encode() runs the same checks as decode(),
so this module never produces a message it would itself reject.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Mapping

MAGIC = b"PK"
VERSION = 1
MAX_MESSAGE_SIZE = 16384
HEADER_SIZE = 4
SIGNATURE_TAG = 0x7F


class MsgType(enum.IntEnum):
    PAIR_REQUEST = 0x01
    PAIR_RESPONSE = 0x02
    AUTH_REQUEST = 0x03
    AUTH_RESPONSE = 0x04
    STATUS = 0x05
    ERROR = 0x06


class ErrorCode(enum.IntEnum):
    MALFORMED = 0x0001
    UNSUPPORTED_VERSION = 0x0002
    UNKNOWN_VERIFIER = 0x0003
    UNKNOWN_DEVICE = 0x0004
    BAD_SIGNATURE = 0x0005
    EXPIRED = 0x0006
    UNKNOWN_REQUEST = 0x0007
    BUSY = 0x0008
    USER_DENIED = 0x0009
    BIOMETRIC_FAILED = 0x000A
    KEY_INVALIDATED = 0x000B
    NOT_PAIRING = 0x000C
    RATE_LIMITED = 0x000D
    INTERNAL = 0x000E
    INSECURE_KEY = 0x000F


class Status(enum.IntEnum):
    READY = 1
    PROMPTING = 2
    PAIRED = 3
    BUSY = 4


class KeySecurity(enum.IntEnum):
    SOFTWARE = 1
    TEE = 2
    STRONGBOX = 3


class ProtocolError(Exception):
    """A protocol rule was violated; `code` is the error to report to the peer."""

    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(f"{code.name}: {detail}")
        self.code = code
        self.detail = detail


class Kind(enum.Enum):
    BYTES = "bytes"
    STRING = "string"
    U8 = 1
    U16 = 2
    U32 = 4
    U64 = 8


@dataclass(frozen=True)
class FieldSpec:
    tag: int
    name: str
    kind: Kind
    min_len: int = 0
    max_len: int = 0


FIELDS = (
    FieldSpec(0x01, "verifier_id", Kind.BYTES, 32, 32),
    FieldSpec(0x02, "device_id", Kind.BYTES, 32, 32),
    FieldSpec(0x03, "request_id", Kind.BYTES, 16, 16),
    FieldSpec(0x04, "challenge", Kind.BYTES, 32, 32),
    FieldSpec(0x05, "action", Kind.STRING, 1, 64),
    FieldSpec(0x06, "resource", Kind.STRING, 1, 256),
    FieldSpec(0x07, "account", Kind.STRING, 1, 64),
    FieldSpec(0x08, "issued_at", Kind.U64),
    FieldSpec(0x09, "ttl_ms", Kind.U32),
    FieldSpec(0x0A, "public_key", Kind.BYTES, 91, 91),
    FieldSpec(0x0B, "display_name", Kind.STRING, 1, 64),
    FieldSpec(0x0C, "pairing_nonce", Kind.BYTES, 32, 32),
    FieldSpec(0x0D, "request_hash", Kind.BYTES, 32, 32),
    FieldSpec(0x0E, "key_security", Kind.U8),
    FieldSpec(0x0F, "attestation_chain", Kind.BYTES, 0, 12288),
    FieldSpec(0x10, "status", Kind.U8),
    FieldSpec(0x11, "error_code", Kind.U16),
    FieldSpec(0x12, "error_detail", Kind.STRING, 0, 128),
    FieldSpec(SIGNATURE_TAG, "signature", Kind.BYTES, 8, 72),
)
FIELDS_BY_TAG = {f.tag: f for f in FIELDS}
FIELDS_BY_NAME = {f.name: f for f in FIELDS}


def _schema(required: str, optional: str = "") -> tuple[frozenset[str], frozenset[str]]:
    return frozenset(required.split()), frozenset(optional.split())


# (required, optional) field names per message type — PROTOCOL.md §4.
SCHEMAS = {
    MsgType.PAIR_REQUEST: _schema(
        "verifier_id action account issued_at ttl_ms public_key display_name pairing_nonce signature"
    ),
    MsgType.PAIR_RESPONSE: _schema(
        "verifier_id device_id public_key display_name pairing_nonce request_hash key_security signature",
        "attestation_chain",
    ),
    MsgType.AUTH_REQUEST: _schema(
        "verifier_id device_id request_id challenge action resource account issued_at ttl_ms signature"
    ),
    MsgType.AUTH_RESPONSE: _schema("verifier_id device_id request_id request_hash signature"),
    MsgType.STATUS: _schema("status", "verifier_id device_id request_id"),
    MsgType.ERROR: _schema("error_code", "request_id error_detail"),
}

SIGNED_TYPES = frozenset(t for t, (req, _) in SCHEMAS.items() if "signature" in req)

# Characters that must never appear in displayed strings (PROTOCOL.md §3.2 rule 5).
_FORBIDDEN_CHARS = frozenset(
    [*range(0x00, 0x20), *range(0x7F, 0xA0), 0x061C, 0x200E, 0x200F,
     *range(0x202A, 0x202F), *range(0x2066, 0x206A)]
)

FieldValue = bytes | str | int


@dataclass(frozen=True)
class Message:
    type: MsgType
    fields: Mapping[str, FieldValue]
    raw: bytes
    # Bytes covered by the signature (everything before the signature TLV), or None.
    signed_part: bytes | None

    def __getitem__(self, name: str) -> FieldValue:
        return self.fields[name]

    def get(self, name: str, default: FieldValue | None = None) -> FieldValue | None:
        return self.fields.get(name, default)


def _malformed(detail: str) -> ProtocolError:
    return ProtocolError(ErrorCode.MALFORMED, detail)


def _check_string(name: str, text: str) -> None:
    for ch in text:
        if ord(ch) in _FORBIDDEN_CHARS:
            raise _malformed(f"{name}: forbidden character U+{ord(ch):04X}")


def _parse_value(spec: FieldSpec, raw: bytes) -> FieldValue:
    if spec.kind in (Kind.U8, Kind.U16, Kind.U32, Kind.U64):
        if len(raw) != spec.kind.value:
            raise _malformed(f"{spec.name}: expected {spec.kind.value} bytes, got {len(raw)}")
        return int.from_bytes(raw, "big")
    if not spec.min_len <= len(raw) <= spec.max_len:
        raise _malformed(f"{spec.name}: length {len(raw)} outside {spec.min_len}..{spec.max_len}")
    if spec.kind is Kind.BYTES:
        return raw
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _malformed(f"{spec.name}: invalid UTF-8") from None
    _check_string(spec.name, text)
    return text


def _encode_value(spec: FieldSpec, value: FieldValue) -> bytes:
    if spec.kind in (Kind.U8, Kind.U16, Kind.U32, Kind.U64):
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{spec.name}: expected int")
        if not 0 <= value < 1 << (8 * spec.kind.value):
            raise _malformed(f"{spec.name}: {value} out of range")
        return value.to_bytes(spec.kind.value, "big")
    if spec.kind is Kind.STRING:
        if not isinstance(value, str):
            raise TypeError(f"{spec.name}: expected str")
        raw = value.encode("utf-8")
    else:
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError(f"{spec.name}: expected bytes")
        raw = bytes(value)
    _parse_value(spec, raw)  # same length/content checks as decoding
    return raw


def _encode(mtype: MsgType, fields: Mapping[str, FieldValue], *, unsigned: bool) -> bytes:
    required, optional = SCHEMAS[mtype]
    if unsigned:
        if mtype not in SIGNED_TYPES:
            raise ValueError(f"{mtype.name} is not a signed message type")
        required = required - {"signature"}
        if "signature" in fields:
            raise ValueError("unsigned encoding must not contain a signature")
    unknown = set(fields) - required - optional
    if unknown:
        raise _malformed(f"fields not allowed in {mtype.name}: {sorted(unknown)}")
    missing = required - set(fields)
    if missing:
        raise _malformed(f"missing fields in {mtype.name}: {sorted(missing)}")

    out = bytearray(MAGIC)
    out += bytes([VERSION, mtype])
    for spec in sorted((FIELDS_BY_NAME[n] for n in fields), key=lambda s: s.tag):
        value = _encode_value(spec, fields[spec.name])
        out += bytes([spec.tag]) + len(value).to_bytes(2, "big") + value
    if len(out) > MAX_MESSAGE_SIZE:
        raise _malformed(f"message too large ({len(out)} bytes)")
    return bytes(out)


def encode(mtype: MsgType, fields: Mapping[str, FieldValue]) -> bytes:
    """Encodes a complete message (including `signature` for signed types)."""
    return _encode(mtype, fields, unsigned=False)


def encode_unsigned(mtype: MsgType, fields: Mapping[str, FieldValue]) -> bytes:
    """Encodes a signed message type without its signature: the bytes to sign."""
    return _encode(mtype, fields, unsigned=True)


def with_signature(unsigned: bytes, signature: bytes) -> bytes:
    """Appends the signature TLV to the output of encode_unsigned()."""
    spec = FIELDS_BY_NAME["signature"]
    data = unsigned + bytes([SIGNATURE_TAG]) + len(signature).to_bytes(2, "big") + _encode_value(spec, signature)
    decode(data)  # validates the result, including the total size
    return data


def decode(data: bytes) -> Message:
    """Parses and validates a message. Raises ProtocolError on any violation."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("expected bytes")
    data = bytes(data)
    if len(data) > MAX_MESSAGE_SIZE:
        raise _malformed(f"message too large ({len(data)} bytes)")
    if len(data) < HEADER_SIZE or data[:2] != MAGIC:
        raise _malformed("bad header")
    if data[2] != VERSION:
        raise ProtocolError(ErrorCode.UNSUPPORTED_VERSION, f"version {data[2]}")
    try:
        mtype = MsgType(data[3])
    except ValueError:
        raise _malformed(f"unknown message type 0x{data[3]:02x}") from None

    required, optional = SCHEMAS[mtype]
    allowed = required | optional
    fields: dict[str, FieldValue] = {}
    pos = HEADER_SIZE
    last_tag = 0
    signed_end: int | None = None
    while pos < len(data):
        if len(data) - pos < 3:
            raise _malformed("truncated field header")
        tag = data[pos]
        length = int.from_bytes(data[pos + 1:pos + 3], "big")
        start, end = pos + 3, pos + 3 + length
        if end > len(data):
            raise _malformed(f"field 0x{tag:02x} overruns message")
        if tag <= last_tag:
            raise _malformed(f"field 0x{tag:02x} out of order or repeated")
        spec = FIELDS_BY_TAG.get(tag)
        if spec is None or spec.name not in allowed:
            raise _malformed(f"field 0x{tag:02x} not allowed in {mtype.name}")
        fields[spec.name] = _parse_value(spec, data[start:end])
        if tag == SIGNATURE_TAG:
            signed_end = pos
        last_tag = tag
        pos = end

    missing = required - fields.keys()
    if missing:
        raise _malformed(f"missing fields in {mtype.name}: {sorted(missing)}")
    return Message(mtype, fields, data, data[:signed_end] if signed_end is not None else None)
