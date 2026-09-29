"""Daemon logic between the BLE transport and local clients (no D-Bus here).

The laptop is the BLE central; each phone is a peripheral. Peers are BLE
connections, identified by an opaque transport handle (the BlueZ device path). A peer is associated with a paired device_id only via the STATUS
READY it sends after subscribing; that claim is used for routing and status
display only. Authorization always rests on the device key's signature.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Protocol

from . import codec, framing
from .codec import ErrorCode, MsgType, ProtocolError, Status
from .verifier import AuthResult, Verifier

log = logging.getLogger(__name__)

Event = dict
EventSink = Callable[[Event], None]


class Transport(Protocol):
    def send(self, peer_id: str, frame: bytes) -> None: ...
    def set_pairing_mode(self, enabled: bool) -> None: ...
    def drop(self, peer_id: str) -> None: ...


class Scheduler(Protocol):
    def call_later(self, seconds: float, callback: Callable[[], None]) -> object: ...
    def cancel(self, handle: object) -> None: ...


HELLO_TIMEOUT = 6.0  # seconds for a phone to answer our subscription or keepalive with STATUS
KEEPALIVE_INTERVAL = 20.0  # detects links that stay up while the phone app restarted


@dataclass
class _Peer:
    reassembler: framing.Reassembler = field(default_factory=framing.Reassembler)
    device_id: bytes | None = None
    att_mtu: int = framing.DEFAULT_ATT_MTU
    greeted: bool = False  # the phone answered our subscription with STATUS
    hello_timer: object = None
    ping_timer: object = None


@dataclass
class _Waiter:
    device_id: bytes
    on_event: EventSink
    timer: object


@dataclass
class _PairingJob:
    request: bytes
    on_event: EventSink
    timer: object
    confirm: Callable[[bool], None] | None = None
    asked: str | None = None  # peer we sent PAIR_REQUEST to (for progress messages)


class DaemonCore:
    def __init__(self, verifier: Verifier, transport: Transport, scheduler: Scheduler):
        self.verifier = verifier
        self._transport = transport
        self._scheduler = scheduler
        self._peers: dict[str, _Peer] = {}
        self._waiters: dict[bytes, _Waiter] = {}
        self._pairing: _PairingJob | None = None
        self._msg_no = 0

    # ---- status --------------------------------------------------------

    def connected_device_ids(self) -> set[bytes]:
        return {p.device_id for p in self._peers.values() if p.device_id is not None}

    def status(self) -> Event:
        connected = self.connected_device_ids()
        return {
            "paired": [
                {"device_id": r.device_id.hex(), "name": r.display_name, "account": r.account,
                 "connected": r.device_id in connected}
                for r in self.verifier.registry.all()
            ],
            "pairing": self._pairing is not None,
            "pending": self.verifier.pending_count,
        }

    # ---- transport events ----------------------------------------------

    def on_connect(self, peer_id: str, att_mtu: int | None = None) -> None:
        """The transport connected and subscribed to a phone."""
        peer = self._peers.setdefault(peer_id, _Peer())
        peer.greeted = False
        if att_mtu:
            peer.att_mtu = att_mtu
        self._cancel_hello(peer)
        peer.hello_timer = self._scheduler.call_later(HELLO_TIMEOUT, lambda: self._check_greeted(peer_id, peer))

    def _cancel_hello(self, peer: _Peer) -> None:
        if peer.hello_timer is not None:
            self._scheduler.cancel(peer.hello_timer)
            peer.hello_timer = None

    def _schedule_ping(self, peer_id: str, peer: _Peer) -> None:
        if peer.ping_timer is not None:
            self._scheduler.cancel(peer.ping_timer)
        peer.ping_timer = self._scheduler.call_later(KEEPALIVE_INTERVAL, lambda: self._ping(peer_id, peer))

    def _ping(self, peer_id: str, peer: _Peer) -> None:
        peer.ping_timer = None
        if self._peers.get(peer_id) is not peer:
            return
        peer.greeted = False
        peer.hello_timer = self._scheduler.call_later(HELLO_TIMEOUT, lambda: self._check_greeted(peer_id, peer))
        self._send(codec.encode(MsgType.STATUS, {"status": Status.READY, "verifier_id": self.verifier.verifier_id}),
                   peer_id)

    def _check_greeted(self, peer_id: str, peer: _Peer) -> None:
        peer.hello_timer = None
        if self._peers.get(peer_id) is peer and not peer.greeted:
            log.info("no STATUS from %s after subscribing; reconnecting", peer_id)
            self._drop(peer_id)

    def _drop(self, peer_id: str) -> None:
        self.on_disconnect(peer_id)
        self._transport.drop(peer_id)

    def on_frame(self, peer_id: str, frame: bytes, att_mtu: int | None = None) -> None:
        peer = self._peers.setdefault(peer_id, _Peer())
        if att_mtu:
            peer.att_mtu = att_mtu
        try:
            message = peer.reassembler.feed(frame)
        except ProtocolError as e:
            log.info("framing error from %s: %s", peer_id, e.detail)
            self._send(codec.encode(MsgType.ERROR, {"error_code": e.code}), peer_id)
            return
        if message is not None:
            self._on_message(peer_id, peer, message)

    def on_disconnect(self, peer_id: str) -> None:
        if self._pairing is not None and self._pairing.asked == peer_id:
            self._pairing.asked = None
            self.pairing_progress("The Bluetooth link dropped; reconnecting. Keep both screens open…")
        peer = self._peers.pop(peer_id, None)
        if peer is not None:
            self._cancel_hello(peer)
            if peer.ping_timer is not None:
                self._scheduler.cancel(peer.ping_timer)
                peer.ping_timer = None
        if peer is None or peer.device_id is None:
            return
        if peer.device_id in self.connected_device_ids():
            return  # still connected through another link
        for request_id, waiter in list(self._waiters.items()):
            if waiter.device_id == peer.device_id:
                self._finish_auth(request_id, {"result": "unavailable", "reason": "phone disconnected"})

    # ---- local requests --------------------------------------------------

    def start_pairing(self, account: str, window: float, on_event: EventSink) -> None:
        if self._pairing is not None:
            on_event({"result": "error", "reason": "pairing already in progress"})
            return
        request = self.verifier.begin_pairing(account=account, window=window)
        timer = self._scheduler.call_later(window, self._pairing_timeout)
        self._pairing = _PairingJob(request, on_event, timer)
        self._transport.set_pairing_mode(True)
        on_event({"event": "waiting", "window": window})

    def on_bond_confirmation(self, peer_id: str, passkey: int, reply: Callable[[bool], None]) -> None:
        """BlueZ asks whether the 6-digit numeric comparison code matches the phone's."""
        if self._pairing is None:
            reply(False)
            return
        if self._pairing.confirm is not None:
            self._pairing.confirm(False)
        self._pairing.confirm = reply
        self._pairing.on_event({"event": "confirm", "passkey": f"{passkey:06d}"})

    def answer_bond_confirmation(self, accepted: bool) -> None:
        if self._pairing is not None and self._pairing.confirm is not None:
            reply, self._pairing.confirm = self._pairing.confirm, None
            reply(bool(accepted))

    def pairing_progress(self, message: str) -> None:
        """Tells the waiting `phonekey pair` what is happening (no effect outside pairing)."""
        if self._pairing is not None:
            self._pairing.on_event({"event": "progress", "message": message})

    def cancel_pairing(self) -> None:
        if self._pairing is not None:
            self._end_pairing({"result": "cancelled"})

    def authenticate(self, account: str, action: str, resource: str, on_event: EventSink,
                     detail: str | None = None) -> bytes | None:
        """Sends an AUTH_REQUEST; returns its request_id (for cancel_auth), or None if not sent."""
        connected = self.connected_device_ids()
        candidates = [r for r in self.verifier.registry.for_account(account) if r.device_id in connected]
        if not candidates:
            on_event({"result": "unavailable", "reason": "no paired phone connected"})
            return None
        device = candidates[0]
        try:
            request_id, message = self.verifier.begin_auth(device.device_id, account=account, action=action,
                                                           resource=resource, detail=detail)
        except ProtocolError as e:
            on_event({"result": "unavailable", "reason": e.code.name})
            return None
        timer = self._scheduler.call_later(
            self.verifier.auth_ttl, lambda: self._auth_timeout(request_id))
        self._waiters[request_id] = _Waiter(device.device_id, on_event, timer)
        on_event({"event": "sent", "device": device.display_name})
        self._send(message, self._peer_id_for(device.device_id))
        return request_id

    def cancel_auth(self, request_id: bytes) -> None:
        """The local caller stopped waiting (e.g. the lock screen gave up, Ctrl-C on sudo).

        The request becomes invalid here at once, and the phone is told to dismiss
        its prompt (ERROR EXPIRED for that request_id, PROTOCOL.md §8.1)."""
        waiter = self._waiters.pop(request_id, None)
        if waiter is None:
            return
        self.verifier.cancel(request_id)
        if waiter.timer is not None:
            self._scheduler.cancel(waiter.timer)
        peer_id = next((pid for pid, p in self._peers.items() if p.device_id == waiter.device_id), None)
        if peer_id is not None:
            self._send(codec.encode(MsgType.ERROR, {"error_code": ErrorCode.EXPIRED, "request_id": request_id}),
                       peer_id)

    # ---- internals -------------------------------------------------------

    def _on_message(self, peer_id: str, peer: _Peer, data: bytes) -> None:
        try:
            msg = codec.decode(data)
        except ProtocolError as e:
            log.info("malformed message from %s: %s", peer_id, e.detail)
            self._send(codec.encode(MsgType.ERROR, {"error_code": e.code}), peer_id)
            return

        if msg.type is MsgType.STATUS:
            self._on_status(peer_id, peer, msg)
        elif msg.type is MsgType.PAIR_RESPONSE or (msg.type is MsgType.ERROR and self._pairing is not None
                                                    and msg.get("request_id") is None):
            self._on_pair_response(peer_id, data)
        elif msg.type in (MsgType.AUTH_RESPONSE, MsgType.ERROR):
            self._on_auth_response(data)
        else:
            self._send(codec.encode(MsgType.ERROR, {"error_code": ErrorCode.MALFORMED}), peer_id)

    def _on_status(self, peer_id: str, peer: _Peer, msg: codec.Message) -> None:
        peer.greeted = True
        self._cancel_hello(peer)
        device_id = msg.get("device_id")
        log.debug("STATUS %s from %s (%s)", msg["status"], peer_id,
                  f"device {device_id[:4].hex()}" if device_id else "no ids")
        if msg.get("verifier_id") == self.verifier.verifier_id and device_id is not None:
            if self.verifier.registry.get(device_id) is not None:
                if peer.device_id != device_id:
                    log.info("paired device %s connected via %s", device_id[:4].hex(), peer_id)
                peer.device_id = device_id
                self._schedule_ping(peer_id, peer)
            return
        if self._pairing is not None:
            log.info("sending PAIR_REQUEST to %s", peer_id)
            self._pairing.asked = peer_id
            self.pairing_progress("Connected. Now approve this computer on your phone (fingerprint).")
            self._send(self._pairing.request, peer_id)  # a phone in pairing mode is asking
        else:
            log.info("ignoring STATUS without ids: no pairing window open")

    def _on_pair_response(self, peer_id: str, data: bytes) -> None:
        log.info("pairing reply (%s) from %s", codec.MsgType(data[3]).name if len(data) > 3 else "?", peer_id)
        if self._pairing is None:
            self._send(codec.encode(MsgType.ERROR, {"error_code": ErrorCode.NOT_PAIRING}), peer_id)
            return
        try:
            record = self.verifier.complete_pairing(data, bond_address=_address_of(peer_id))
        except ProtocolError as e:
            log.warning("pairing refused: %s", e)
            self._end_pairing({"result": "error", "reason": e.code.name})
            return
        self._send(codec.encode(MsgType.STATUS, {
            "status": Status.PAIRED, "verifier_id": self.verifier.verifier_id, "device_id": record.device_id,
        }), peer_id)
        peer = self._peers.get(peer_id)
        if peer is not None:
            peer.device_id = record.device_id
        self._end_pairing({"result": "paired", "device_id": record.device_id.hex(), "name": record.display_name,
                           "key_security": record.key_security.name, "attestation": record.attestation})

    def _on_auth_response(self, data: bytes) -> None:
        result = self.verifier.complete_auth(data)
        if result.request_id is None or result.request_id not in self._waiters:
            log.info("ignored auth message: %s", result.error.name if result.error else "no waiter")
            return
        self._finish_auth(result.request_id, _auth_event(result))

    def _auth_timeout(self, request_id: bytes) -> None:
        self.verifier.cancel(request_id)
        if request_id in self._waiters:
            waiter = self._waiters[request_id]
            waiter.timer = None
            self._finish_auth(request_id, {"result": "unavailable", "reason": "timed out"})
            # A silent phone may be behind a stale link: reconnect for the next attempt.
            peer_id = next((pid for pid, p in self._peers.items() if p.device_id == waiter.device_id), None)
            if peer_id is not None:
                self._drop(peer_id)

    def _finish_auth(self, request_id: bytes, event: Event) -> None:
        waiter = self._waiters.pop(request_id)
        self.verifier.cancel(request_id)
        if waiter.timer is not None:
            self._scheduler.cancel(waiter.timer)
        waiter.on_event(event)

    def _pairing_timeout(self) -> None:
        if self._pairing is not None:
            self._pairing.timer = None
            self._end_pairing({"result": "error", "reason": "EXPIRED"})

    def _end_pairing(self, event: Event) -> None:
        job, self._pairing = self._pairing, None
        if job.confirm is not None:
            job.confirm(False)
        self.verifier.close_pairing()
        if job.timer is not None:
            self._scheduler.cancel(job.timer)
        self._transport.set_pairing_mode(False)
        job.on_event(event)

    def _peer_id_for(self, device_id: bytes) -> str:
        return next(pid for pid, p in self._peers.items() if p.device_id == device_id)

    def _send(self, message: bytes, peer_id: str) -> None:
        peer = self._peers.get(peer_id)
        att_mtu = peer.att_mtu if peer is not None else framing.DEFAULT_ATT_MTU
        self._msg_no = (self._msg_no + 1) & 0xFF
        for frame in framing.fragment(message, self._msg_no, framing.max_payload(att_mtu)):
            self._transport.send(peer_id, frame)


def _auth_event(result: AuthResult) -> Event:
    if result.ok:
        return {"result": "ok"}
    denied = {ErrorCode.USER_DENIED, ErrorCode.BIOMETRIC_FAILED}
    unavailable = {ErrorCode.BUSY, ErrorCode.RATE_LIMITED, ErrorCode.KEY_INVALIDATED, ErrorCode.EXPIRED}
    kind = "denied" if result.error in denied else "unavailable" if result.error in unavailable else "error"
    return {"result": kind, "reason": result.error.name}


def _address_of(peer_id: str) -> str | None:
    """BlueZ device paths end in dev_AA_BB_CC_DD_EE_FF; metadata only."""
    tail = peer_id.rsplit("/", 1)[-1]
    return tail[4:].replace("_", ":") if tail.startswith("dev_") else None
