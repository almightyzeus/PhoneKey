"""Minimal ATT client for the PhoneKey service (Bluetooth Core Vol 3 Part F).

Used on an L2CAP LE socket that the daemon opens itself, so the link is always
LE (BlueZ's Device1.Connect picks classic Bluetooth for dual-mode phones) and
never carries other profiles. Only what PhoneKey needs: MTU exchange, finding
one service and its two characteristics, enabling indications, write requests,
and confirming indications. Requests from the phone are answered minimally.

Pure protocol logic: bytes in via feed(), bytes out via the `send` callback.
"""

from __future__ import annotations

import collections
import struct
import uuid as uuidlib
from typing import Callable

# Opcodes
ERROR_RSP = 0x01
MTU_REQ, MTU_RSP = 0x02, 0x03
FIND_INFO_REQ, FIND_INFO_RSP = 0x04, 0x05
FIND_BY_TYPE_REQ, FIND_BY_TYPE_RSP = 0x06, 0x07
READ_BY_TYPE_REQ, READ_BY_TYPE_RSP = 0x08, 0x09
WRITE_REQ, WRITE_RSP = 0x12, 0x13
NOTIFY, INDICATE, CONFIRM = 0x1B, 0x1D, 0x1E
WRITE_CMD = 0x52

ERR_REQUEST_NOT_SUPPORTED = 0x06
ERR_ATTRIBUTE_NOT_FOUND = 0x0A

PRIMARY_SERVICE = 0x2800
CHARACTERISTIC = 0x2803
CCCD = 0x2902
CCCD_INDICATE = b"\x02\x00"

CLIENT_MTU = 517
DEFAULT_MTU = 23


class AttError(Exception):
    pass


def uuid128_le(value: str) -> bytes:
    """ATT carries 128-bit UUIDs little-endian."""
    return uuidlib.UUID(value).bytes[::-1]


class AttClient:
    """Sets up the PhoneKey service, then carries frames both ways."""

    def __init__(self, service_uuid: str, notify_uuid: str, write_uuid: str,
                 send: Callable[[bytes], None],
                 on_ready: Callable[[int], None],
                 on_value: Callable[[bytes], None],
                 on_error: Callable[[str], None]):
        self._service = uuid128_le(service_uuid)
        self._notify_uuid = uuid128_le(notify_uuid)
        self._write_uuid = uuid128_le(write_uuid)
        self._send, self._on_ready, self._on_value, self._on_error = send, on_ready, on_value, on_error
        self.mtu = DEFAULT_MTU
        self.ready = False
        self._pending: tuple[int, Callable[[int, bytes], None]] | None = None  # (expected rsp opcode, handler)
        self._queue: collections.deque = collections.deque()
        self._chars: list[tuple[int, int, bytes]] = []  # (declaration handle, value handle, uuid)
        self._svc_end = 0
        self.notify_handle = self.write_handle = self.cccd_handle = 0
        self._failed = False

    # ---- public ----------------------------------------------------------

    def start(self) -> None:
        self._request(bytes([MTU_REQ]) + struct.pack("<H", CLIENT_MTU), MTU_RSP, self._mtu_done)

    def write(self, value: bytes) -> None:
        """Queues a Write Request to the phone's write characteristic."""
        if not self.ready:
            raise AttError("not ready")
        self._request(bytes([WRITE_REQ]) + struct.pack("<H", self.write_handle) + value, WRITE_RSP,
                      lambda op, body: None)

    def feed(self, pdu: bytes) -> None:
        if not pdu or self._failed:
            return
        op = pdu[0]
        if op == INDICATE:
            self._send(bytes([CONFIRM]))
            self._value(pdu)
        elif op == NOTIFY:
            self._value(pdu)
        elif op == MTU_REQ:  # the phone's own GATT client
            self._send(bytes([MTU_RSP]) + struct.pack("<H", CLIENT_MTU))
        elif self._is_request(op):
            # Any other request from the phone: this laptop exposes no GATT database here.
            code = ERR_ATTRIBUTE_NOT_FOUND if op in (FIND_INFO_REQ, FIND_BY_TYPE_REQ, READ_BY_TYPE_REQ, 0x10) \
                else ERR_REQUEST_NOT_SUPPORTED
            self._send(bytes([ERROR_RSP, op, 0, 0, code]))
        elif op in (WRITE_CMD, CONFIRM) or op & 0x40:
            pass  # commands need no reply
        else:
            self._response(op, pdu[1:])

    # ---- request/response plumbing ----------------------------------------

    @staticmethod
    def _is_request(op: int) -> bool:
        return op in (0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x16, 0x18, 0x20)

    def _request(self, pdu: bytes, expected: int, handler: Callable[[int, bytes], None]) -> None:
        self._queue.append((pdu, expected, handler))
        self._pump()

    def _pump(self) -> None:
        if self._pending is None and self._queue:
            pdu, expected, handler = self._queue.popleft()
            self._pending = (expected, handler)
            self._send(pdu)

    def _response(self, op: int, body: bytes) -> None:
        if self._pending is None:
            return  # unsolicited response: ignore
        expected, handler = self._pending
        if op not in (expected, ERROR_RSP):
            return
        self._pending = None
        try:
            handler(op, body)
        except (struct.error, IndexError) as e:
            self._fail(f"malformed ATT response: {e}")
            return
        self._pump()

    def _fail(self, reason: str) -> None:
        if not self._failed:
            self._failed = True
            self._on_error(reason)

    def _value(self, pdu: bytes) -> None:
        if len(pdu) >= 3 and self.ready and struct.unpack_from("<H", pdu, 1)[0] == self.notify_handle:
            self._on_value(pdu[3:])

    # ---- setup sequence --------------------------------------------------

    def _mtu_done(self, op: int, body: bytes) -> None:
        if op == MTU_RSP:
            self.mtu = max(DEFAULT_MTU, min(CLIENT_MTU, struct.unpack_from("<H", body)[0]))
        self._request(bytes([FIND_BY_TYPE_REQ]) + struct.pack("<HHH", 1, 0xFFFF, PRIMARY_SERVICE) + self._service,
                      FIND_BY_TYPE_RSP, self._service_found)

    def _service_found(self, op: int, body: bytes) -> None:
        if op == ERROR_RSP or len(body) < 4:
            self._fail("PhoneKey service not found on the phone")
            return
        start, end = struct.unpack_from("<HH", body)
        self._svc_end = end
        self._read_chars(start)

    def _read_chars(self, start: int) -> None:
        self._request(bytes([READ_BY_TYPE_REQ]) + struct.pack("<HHH", start, self._svc_end, CHARACTERISTIC),
                      READ_BY_TYPE_RSP, self._chars_read)

    def _chars_read(self, op: int, body: bytes) -> None:
        if op == READ_BY_TYPE_RSP:
            length, data = body[0], body[1:]
            last = 0
            for i in range(0, len(data) - length + 1, length):
                decl, _props, value_handle = struct.unpack_from("<HBH", data, i)
                self._chars.append((decl, value_handle, bytes(data[i + 5:i + length])))
                last = value_handle
            if last and last < self._svc_end:
                self._read_chars(last + 1)
                return
        for decl, value_handle, uuid in self._chars:
            if uuid == self._notify_uuid:
                self.notify_handle = value_handle
            elif uuid == self._write_uuid:
                self.write_handle = value_handle
        if not self.notify_handle or not self.write_handle:
            self._fail("PhoneKey characteristics not found on the phone")
            return
        following = [d for d, _, _ in self._chars if d > self.notify_handle]
        end = min(following) - 1 if following else self._svc_end
        self._request(bytes([FIND_INFO_REQ]) + struct.pack("<HH", self.notify_handle + 1, end),
                      FIND_INFO_RSP, self._descriptors_found)

    def _descriptors_found(self, op: int, body: bytes) -> None:
        if op == FIND_INFO_RSP and body and body[0] == 1:  # 16-bit UUIDs
            for i in range(1, len(body) - 3, 4):
                handle, uuid16 = struct.unpack_from("<HH", body, i)
                if uuid16 == CCCD:
                    self.cccd_handle = handle
        if not self.cccd_handle:
            self._fail("indication descriptor not found on the phone")
            return
        self._request(bytes([WRITE_REQ]) + struct.pack("<H", self.cccd_handle) + CCCD_INDICATE,
                      WRITE_RSP, self._subscribed)

    def _subscribed(self, op: int, body: bytes) -> None:
        if op == ERROR_RSP:
            self._fail(f"phone refused the subscription (ATT error 0x{body[3]:02x})" if len(body) >= 4
                       else "phone refused the subscription")
            return
        self.ready = True
        self._on_ready(self.mtu)
