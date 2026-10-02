"""When the laptop scans for phones (pure logic; ble.py applies it).

Continuous LE discovery made the MVP laptop's Realtek RTL8822CU stop answering
"disable scanning" (kernel: `Opcode 0x2042 failed: -110`) after an hour or two,
which also broke the kernel's background scan that other Bluetooth devices
(e.g. a BLE mouse) need to reconnect. So scanning is kept to what is needed:

- off while every paired phone is connected, and when nothing is paired;
- short bursts while a paired phone is missing: often at first, then rarely;
- one burst right away when someone needs the phone (sudo, unlock, test);
- continuous only during a `phonekey pair` window (two minutes).

The numbers are starting points, to be tuned in ROADMAP Phase 7.
"""

from __future__ import annotations

BURST = 12.0           # seconds of scanning per burst
RECENT_PAUSE = 30.0    # pause between bursts during the first RECENT_WINDOW after a phone went missing
LONG_PAUSE = 120.0     # pause between bursts after that
RECENT_WINDOW = 300.0

OFF, SCAN, PAIRING = "off", "scan", "pairing"


class ScanPolicy:
    def __init__(self) -> None:
        self._missing_since: float | None = None
        self._burst_until: float | None = None
        self._next_burst = 0.0

    def wake(self, now: float) -> None:
        """Someone is waiting for a phone: scan at the next decision."""
        self._next_burst = min(self._next_burst, now)

    def decide(self, now: float, pairing: bool, missing: int) -> str:
        """OFF, SCAN (a burst) or PAIRING. Called on events and on a regular tick."""
        if pairing:
            return PAIRING
        if missing <= 0:
            self._missing_since = self._burst_until = None
            self._next_burst = now  # a phone that goes missing later is looked for at once
            return OFF
        if self._missing_since is None:
            self._missing_since = now
        if self._burst_until is not None:
            if now < self._burst_until:
                return SCAN
            pause = RECENT_PAUSE if now - self._missing_since < RECENT_WINDOW else LONG_PAUSE
            self._burst_until = None
            self._next_burst = max(self._next_burst, now + pause)
            return OFF
        if now >= self._next_burst:
            self._burst_until = now + BURST
            return SCAN
        return OFF
