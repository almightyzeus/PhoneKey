"""BLE message framing (protocol/PROTOCOL.md §6.2).

Frame: msg_no (u8) | frag (u8) | flags (u8, bit 0 = LAST) | payload.
"""

from __future__ import annotations

import time
from typing import Callable

from .codec import MAX_MESSAGE_SIZE, ErrorCode, ProtocolError

HEADER_SIZE = 3
FLAG_LAST = 0x01
MAX_FRAGMENTS = 255
REASSEMBLY_TIMEOUT = 5.0
ATT_HEADER = 3  # ATT opcode + handle
DEFAULT_ATT_MTU = 23
# 244 = one LE data PDU with Data Length Extension (251) minus L2CAP (4) and ATT (3)
# headers. Larger frames span several link-layer PDUs, which some controllers
# (the MVP laptop's Realtek RTL8822CU) do not sustain: the link timed out mid-burst.
MAX_FRAME = 244


def max_payload(att_mtu: int) -> int:
    frame = min(att_mtu - ATT_HEADER, MAX_FRAME)
    return max(1, frame - HEADER_SIZE)


def fragment(message: bytes, msg_no: int, payload_size: int) -> list[bytes]:
    if not message:
        raise ValueError("empty message")
    chunks = [message[i:i + payload_size] for i in range(0, len(message), payload_size)]
    if len(chunks) > MAX_FRAGMENTS:
        raise ValueError(f"message needs {len(chunks)} fragments (max {MAX_FRAGMENTS})")
    return [
        bytes([msg_no & 0xFF, i, FLAG_LAST if i == len(chunks) - 1 else 0]) + chunk
        for i, chunk in enumerate(chunks)
    ]


class Reassembler:
    """Collects frames from one peer. Any rule violation discards the partial message."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._reset()

    def _reset(self) -> None:
        self._msg_no: int | None = None
        self._next_frag = 0
        self._started = 0.0
        self._buffer = bytearray()

    def reset(self) -> None:
        self._reset()

    def _fail(self, detail: str) -> ProtocolError:
        self._reset()
        return ProtocolError(ErrorCode.MALFORMED, detail)

    def feed(self, frame: bytes) -> bytes | None:
        """Returns the complete message when LAST arrives, else None."""
        if len(frame) < HEADER_SIZE + 1:
            raise self._fail("frame too short")
        msg_no, frag, flags = frame[0], frame[1], frame[2]
        if flags & ~FLAG_LAST:
            raise self._fail("reserved frame flags set")
        if self._msg_no is not None and self._clock() - self._started > REASSEMBLY_TIMEOUT:
            self._reset()  # stale partial message: drop it and treat this frame as new
        if self._msg_no is None:
            if frag != 0:
                raise self._fail("message does not start at fragment 0")
            self._msg_no, self._started = msg_no, self._clock()
        elif msg_no != self._msg_no or frag != self._next_frag:
            raise self._fail("frame out of order")
        if len(self._buffer) + len(frame) - HEADER_SIZE > MAX_MESSAGE_SIZE:
            raise self._fail("message too large")
        self._buffer += frame[HEADER_SIZE:]
        self._next_frag = frag + 1
        if flags & FLAG_LAST:
            message = bytes(self._buffer)
            self._reset()
            return message
        if self._next_frag >= MAX_FRAGMENTS:
            raise self._fail("too many fragments")
        return None
