"""Software stand-in for the Android authenticator (protocol/PROTOCOL.md §5.2, §8.2).

FOR TESTS AND `phonekey test --simulate` ONLY. Its key lives in memory, is never
written to disk, and reports key_security=SOFTWARE, which a normal Verifier
refuses to pair. It also serves as a reference for the Android implementation.
"""

from __future__ import annotations

from . import codec, crypto
from .codec import ErrorCode, KeySecurity, MsgType, ProtocolError


class SimulatedAuthenticator:
    def __init__(self, display_name: str = "Simulated phone"):
        self.display_name = display_name
        self._key = crypto.generate_key()
        self.spki = crypto.spki_of(self._key.public_key())
        self.device_id = crypto.key_id(self.spki)
        self._verifiers: dict[bytes, crypto.PublicKey] = {}  # verifier_id -> key
        self.prompts: list[dict] = []  # what a user would have been shown

    def handle_pair_request(self, data: bytes) -> bytes:
        msg = codec.decode(data)
        if msg.type is not MsgType.PAIR_REQUEST:
            raise ProtocolError(ErrorCode.MALFORMED, f"expected PAIR_REQUEST, got {msg.type.name}")
        verifier_key = crypto.load_public_key(msg["public_key"])
        if msg["verifier_id"] != crypto.key_id(msg["public_key"]):
            raise ProtocolError(ErrorCode.MALFORMED, "verifier_id does not match public key")
        if not crypto.verify(verifier_key, crypto.LABEL_PAIR_REQUEST, msg.signed_part, msg["signature"]):
            raise ProtocolError(ErrorCode.BAD_SIGNATURE, "bad verifier signature")
        self._verifiers[msg["verifier_id"]] = verifier_key

        unsigned = codec.encode_unsigned(MsgType.PAIR_RESPONSE, {
            "verifier_id": msg["verifier_id"],
            "device_id": self.device_id,
            "public_key": self.spki,
            "display_name": self.display_name,
            "pairing_nonce": msg["pairing_nonce"],
            "request_hash": crypto.sha256(data),
            "key_security": KeySecurity.SOFTWARE,
        })
        return codec.with_signature(unsigned, crypto.sign(self._key, crypto.LABEL_PAIR_RESPONSE, unsigned))

    def handle_auth_request(self, data: bytes, *, approve: bool = True) -> bytes:
        """Returns AUTH_RESPONSE, or ERROR without prompting for anything suspicious."""
        try:
            msg = codec.decode(data)
        except ProtocolError as e:
            return error(e.code)
        if msg.type is not MsgType.AUTH_REQUEST:
            return error(ErrorCode.MALFORMED)
        request_id = msg["request_id"]
        verifier_key = self._verifiers.get(msg["verifier_id"])
        if verifier_key is None:
            return error(ErrorCode.UNKNOWN_VERIFIER, request_id)
        if not crypto.verify(verifier_key, crypto.LABEL_AUTH_REQUEST, msg.signed_part, msg["signature"]):
            return error(ErrorCode.BAD_SIGNATURE, request_id)
        if msg["device_id"] != self.device_id:
            return error(ErrorCode.UNKNOWN_DEVICE, request_id)

        self.prompts.append({k: msg[k] for k in ("action", "resource", "account")})
        if not approve:
            return error(ErrorCode.USER_DENIED, request_id)

        unsigned = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
            "verifier_id": msg["verifier_id"],
            "device_id": self.device_id,
            "request_id": request_id,
            "request_hash": crypto.sha256(data),
        })
        return codec.with_signature(unsigned, crypto.sign(self._key, crypto.LABEL_AUTH_ASSERTION, unsigned))


def error(code: ErrorCode, request_id: bytes | None = None) -> bytes:
    fields: dict = {"error_code": code}
    if request_id is not None:
        fields["request_id"] = request_id
    return codec.encode(MsgType.ERROR, fields)
