"""Local-presence check for sudo approvals (SECURITY.md R-8, D-15).

PhoneKey should prompt the phone only for someone sitting at this laptop, not
for an SSH login, a cron job or a background service running as the user.
Those get the password prompt instead. Facts come from systemd-logind and
/proc for the process that connected (SO_PEERCRED pid, i.e. sudo):

- The process is inside a logind session: the session must be local
  (Remote=no), belong to the account, and be active (in the foreground).
- It is in no session: desktop terminals run under the user's service
  manager (user@UID.service), outside the login session. Then the process
  must have a controlling terminal (cron and background services have none)
  AND the account must have an active local session right now.

This is a hurdle, not a boundary: code already running as the user can
allocate a terminal inside the user's service manager (e.g. via
`systemd-run --user --pty`). Every lookup failure refuses (password prompt).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

LOGIND = "org.freedesktop.login1"
LOGIND_PATH = "/org/freedesktop/login1"
MANAGER = "org.freedesktop.login1.Manager"
SESSION = "org.freedesktop.login1.Session"


@dataclass(frozen=True)
class Session:
    name: str      # user name
    remote: bool
    active: bool
    seat: str      # "" when the session has no seat (e.g. SSH)


def decide(account: str, session: Session | None, has_tty: bool, local_sessions: list[Session]) -> str | None:
    """None if the request may reach the phone, else the reason it may not."""
    if session is not None:
        if session.remote:
            return "remote session (e.g. SSH)"
        if session.name != account:
            return "session belongs to another user"
        if not session.active:
            return "session is not in the foreground"
        return None
    if not has_tty:
        return "no terminal (background job or service)"
    if not any(s.name == account and not s.remote and s.active and s.seat for s in local_sessions):
        return f"{account} is not logged in at this computer"
    return None


def has_tty(pid: int, proc: Path = Path("/proc")) -> bool:
    """Whether the process has a controlling terminal (field 7 of /proc/PID/stat)."""
    try:
        stat = (proc / str(pid) / "stat").read_text()
    except OSError:
        return False
    # The command name (field 2) is in parentheses and may contain spaces or ')'.
    fields = stat[stat.rfind(")") + 2:].split()
    try:
        return int(fields[4]) != 0  # fields[0] is field 3 (state), so field 7 is fields[4]
    except (IndexError, ValueError):
        return False


class Logind:
    """Read-only queries to systemd-logind over the system bus."""

    def __init__(self, bus):
        import dbus

        self._dbus = dbus
        self._bus = bus
        self._manager = dbus.Interface(bus.get_object(LOGIND, LOGIND_PATH), MANAGER)

    def _session(self, path) -> Session:
        props = self._dbus.Interface(self._bus.get_object(LOGIND, path), "org.freedesktop.DBus.Properties")
        p = props.GetAll(SESSION)
        return Session(str(p["Name"]), bool(p["Remote"]), bool(p["Active"]), str(p["Seat"][0]))

    def session_of(self, pid: int) -> Session | None:
        try:
            path = self._manager.GetSessionByPID(self._dbus.UInt32(pid))
        except self._dbus.exceptions.DBusException as e:
            if e.get_dbus_name() == "org.freedesktop.login1.NoSessionForPID":
                return None
            raise
        return self._session(path)

    def sessions(self) -> list[Session]:
        return [self._session(path) for _id, _uid, _user, _seat, path in self._manager.ListSessions()]


def checker(logind: Logind, proc: Path = Path("/proc")) -> Callable[[int, str], str | None]:
    """check(pid, account) -> None if allowed, else the reason. Fails closed."""
    def check(pid: int, account: str) -> str | None:
        try:
            session = logind.session_of(pid)
            local = [] if session is not None else logind.sessions()
        except Exception as e:  # D-Bus down, process gone, ...: refuse
            return f"cannot determine the session ({e.__class__.__name__})"
        return decide(account, session, has_tty(pid, proc), local)
    return check
