"""Verifier side of the PhoneKey protocol (protocol/PROTOCOL.md §5.2, §8.1).

Transport-agnostic: callers pass message bytes in and out. Pending challenges
live only in memory, are single-use, and expire on a monotonic clock.
"""

from __future__ import annotations

import datetime
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from . import attestation, codec, crypto
from .codec import ErrorCode, KeySecurity, MsgType, ProtocolError
from .registry import DeviceRecord, Registry

DEFAULT_AUTH_TTL = 30.0
DEFAULT_PAIRING_WINDOW = 120.0
PAIR_ACTION = "phonekey.pair"


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    error: ErrorCode | None = None
    device_id: bytes | None = None
    request_id: bytes | None = None


@dataclass(frozen=True)
class _PendingAuth:
    device_id: bytes
    account: str
    request_hash: bytes
    deadline: float


@dataclass(frozen=True)
class _PairingSession:
    account: str
    nonce: bytes
    request_hash: bytes
    deadline: float


class Verifier:
    def __init__(
        self,
        key: crypto.PrivateKey,
        registry: Registry,
        *,
        display_name: str,
        auth_ttl: float = DEFAULT_AUTH_TTL,
        clock: Callable[[], float] = time.monotonic,
        allow_software_keys: bool = False,
    ):
        self._key = key
        self.registry = registry
        self.display_name = display_name
        self.auth_ttl = auth_ttl
        self._clock = clock
        self._allow_software_keys = allow_software_keys
        self.spki = crypto.spki_of(key.public_key())
        self.verifier_id = crypto.key_id(self.spki)
        self._pending: dict[bytes, _PendingAuth] = {}
        self._pairing: _PairingSession | None = None

    # ---- authentication -------------------------------------------------

    def begin_auth(self, device_id: bytes, *, account: str, action: str, resource: str,
                   detail: str | None = None) -> tuple[bytes, bytes]:
        """Creates a signed AUTH_REQUEST. Returns (request_id, message bytes).

        `detail` (e.g. the sudo command line) is shown by the phone and covered
        by both signatures; the caller must have made it display-safe."""
        self._expire()
        record = self.registry.get(device_id)
        if record is None or record.account != account:
            raise ProtocolError(ErrorCode.UNKNOWN_DEVICE, "device not paired for this account")
        if any(p.device_id == device_id for p in self._pending.values()):
            raise ProtocolError(ErrorCode.BUSY, "a request is already pending for this device")

        request_id = secrets.token_bytes(16)
        fields = {
            "verifier_id": self.verifier_id,
            "device_id": device_id,
            "request_id": request_id,
            "challenge": secrets.token_bytes(32),
            "action": action,
            "resource": resource,
            "account": account,
            "issued_at": _now_ms(),
            "ttl_ms": int(self.auth_ttl * 1000),
        }
        if detail is not None:
            fields["detail"] = detail
        unsigned = codec.encode_unsigned(MsgType.AUTH_REQUEST, fields)
        message = codec.with_signature(unsigned, crypto.sign(self._key, crypto.LABEL_AUTH_REQUEST, unsigned))
        self._pending[request_id] = _PendingAuth(
            device_id, account, crypto.sha256(message), self._clock() + self.auth_ttl
        )
        return request_id, message

    def complete_auth(self, data: bytes) -> AuthResult:
        """Checks an AUTH_RESPONSE (or ERROR) from the authenticator. Never raises."""
        try:
            msg = codec.decode(data)
        except ProtocolError as e:
            return AuthResult(False, e.code)

        if msg.type is MsgType.ERROR:
            request_id = msg.get("request_id")
            if request_id is not None:
                self._pending.pop(request_id, None)
            return AuthResult(False, _peer_error(msg["error_code"]), request_id=request_id)
        if msg.type is not MsgType.AUTH_RESPONSE:
            return AuthResult(False, ErrorCode.MALFORMED)

        request_id = msg["request_id"]
        # Single use: removed before any other check, whether or not they pass.
        pending = self._pending.pop(request_id, None)
        if pending is None:
            return AuthResult(False, ErrorCode.UNKNOWN_REQUEST, request_id=request_id)

        def fail(code: ErrorCode) -> AuthResult:
            return AuthResult(False, code, pending.device_id, request_id)

        if self._clock() > pending.deadline:
            return fail(ErrorCode.EXPIRED)
        if msg["verifier_id"] != self.verifier_id:
            return fail(ErrorCode.UNKNOWN_VERIFIER)
        if msg["device_id"] != pending.device_id:
            return fail(ErrorCode.UNKNOWN_DEVICE)
        if msg["request_hash"] != pending.request_hash:
            return fail(ErrorCode.BAD_SIGNATURE)
        record = self.registry.get(pending.device_id)  # re-read: unpair is immediate
        if record is None or record.account != pending.account:
            return fail(ErrorCode.UNKNOWN_DEVICE)
        public_key = crypto.load_public_key(record.public_key)
        if not crypto.verify(public_key, crypto.LABEL_AUTH_ASSERTION, msg.signed_part, msg["signature"]):
            return fail(ErrorCode.BAD_SIGNATURE)
        return AuthResult(True, None, pending.device_id, request_id)

    def cancel(self, request_id: bytes) -> None:
        """Drops a pending request (timeout, disconnect)."""
        self._pending.pop(request_id, None)

    @property
    def pending_count(self) -> int:
        self._expire()
        return len(self._pending)

    def _expire(self) -> None:
        now = self._clock()
        for request_id in [r for r, p in self._pending.items() if now > p.deadline]:
            del self._pending[request_id]

    # ---- pairing --------------------------------------------------------

    def begin_pairing(self, *, account: str, window: float = DEFAULT_PAIRING_WINDOW) -> bytes:
        """Opens a pairing window and returns the signed PAIR_REQUEST."""
        nonce = secrets.token_bytes(32)
        unsigned = codec.encode_unsigned(MsgType.PAIR_REQUEST, {
            "verifier_id": self.verifier_id,
            "action": PAIR_ACTION,
            "account": account,
            "issued_at": _now_ms(),
            "ttl_ms": int(window * 1000),
            "public_key": self.spki,
            "display_name": self.display_name,
            "pairing_nonce": nonce,
        })
        message = codec.with_signature(unsigned, crypto.sign(self._key, crypto.LABEL_PAIR_REQUEST, unsigned))
        self._pairing = _PairingSession(account, nonce, crypto.sha256(message), self._clock() + window)
        return message

    def close_pairing(self) -> None:
        self._pairing = None

    def complete_pairing(self, data: bytes, *, bond_address: str | None = None) -> DeviceRecord:
        """Checks a PAIR_RESPONSE and registers the device. Raises ProtocolError.

        The pairing session is consumed by the first response, valid or not.
        """
        session, self._pairing = self._pairing, None
        if session is None:
            raise ProtocolError(ErrorCode.NOT_PAIRING, "no pairing window open")
        msg = codec.decode(data)
        if msg.type is MsgType.ERROR:
            raise ProtocolError(_peer_error(msg["error_code"]), "authenticator refused pairing")
        if msg.type is not MsgType.PAIR_RESPONSE:
            raise ProtocolError(ErrorCode.MALFORMED, f"unexpected {msg.type.name}")
        if self._clock() > session.deadline:
            raise ProtocolError(ErrorCode.EXPIRED, "pairing window closed")
        if msg["verifier_id"] != self.verifier_id:
            raise ProtocolError(ErrorCode.UNKNOWN_VERIFIER, "response is for another verifier")
        if msg["pairing_nonce"] != session.nonce or msg["request_hash"] != session.request_hash:
            raise ProtocolError(ErrorCode.BAD_SIGNATURE, "response does not match this pairing request")

        spki = msg["public_key"]
        try:
            public_key = crypto.load_public_key(spki)
        except ValueError as e:
            raise ProtocolError(ErrorCode.MALFORMED, str(e)) from None
        if msg["device_id"] != crypto.key_id(spki):
            raise ProtocolError(ErrorCode.MALFORMED, "device_id does not match public key")
        if not crypto.verify(public_key, crypto.LABEL_PAIR_RESPONSE, msg.signed_part, msg["signature"]):
            raise ProtocolError(ErrorCode.BAD_SIGNATURE, "proof of possession failed")
        try:
            key_security = KeySecurity(msg["key_security"])
        except ValueError:
            raise ProtocolError(ErrorCode.MALFORMED, "unknown key_security") from None
        if key_security is KeySecurity.SOFTWARE and not self._allow_software_keys:
            raise ProtocolError(ErrorCode.INSECURE_KEY, "device key is not hardware-backed")

        record = DeviceRecord(
            device_id=msg["device_id"],
            public_key=spki,
            account=session.account,
            display_name=msg["display_name"],
            paired_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            key_security=key_security,
            attestation=attestation.summarize(msg.get("attestation_chain"), session.request_hash),
            bond_address=bond_address,
        )
        self.registry.add(record)
        return record


def _peer_error(code: int) -> ErrorCode:
    try:
        return ErrorCode(code)
    except ValueError:
        return ErrorCode.INTERNAL


def _now_ms() -> int:
    return time.time_ns() // 1_000_000
