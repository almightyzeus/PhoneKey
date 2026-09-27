"""The command a sudo request is for, as the phone shows it (SECURITY.md R-8, D-13).

The daemon reads it itself from /proc/<pid>/cmdline of the process that
connected (SO_PEERCRED). No client can supply this text. It is used only for
callers running as root whose process name is sudo/sudoedit: that process is
blocked in PAM while we read it, and only root can change its argv.

The text is made display-safe (no control or bidi characters, ≤ 256 UTF-8
bytes). Truncation is always visible, never silent.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from .codec import FORBIDDEN_CHARS

MAX_BYTES = 256
SUDO_NAMES = ("sudo", "sudoedit")


def _escape(text: str) -> str:
    out = []
    for ch in text:
        cp = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif cp in FORBIDDEN_CHARS:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    return "".join(out)


def describe(name: str, args: list[bytes]) -> str:
    """`name` plus shell-quoted arguments, escaped and truncated to MAX_BYTES."""
    words = [name] + [a.decode("utf-8", errors="backslashreplace") for a in args]
    text = _escape(shlex.join(words))
    data = text.encode()
    if len(data) <= MAX_BYTES:
        return text
    # Leave room for the marker, cut on a character boundary.
    for keep in range(MAX_BYTES - 32, 0, -1):
        head = data[:keep].decode("utf-8", errors="ignore")
        marker = f" … [+{len(text) - len(head)} more characters]"
        if len((head + marker).encode()) <= MAX_BYTES:
            return head + marker
    raise AssertionError("unreachable")


def sudo_command(pid: int, proc: Path = Path("/proc")) -> str | None:
    """The display text for the sudo process `pid`, or None if it is not sudo or unreadable."""
    try:
        name = (proc / str(pid) / "comm").read_text().strip()
        argv = (proc / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    if name not in SUDO_NAMES:
        return None
    if argv and argv[-1] == b"":
        argv = argv[:-1]
    if not argv:
        return None
    return describe(name, argv[1:])
