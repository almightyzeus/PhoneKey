"""phonekeyd: BLE verifier daemon with a local Unix-socket API.

Development mode (default): runs as the invoking user, state in
~/.local/state/phonekey-dev, socket in $XDG_RUNTIME_DIR/phonekey/. Only the
same user may connect. System mode (installed by scripts/install.sh) runs as
the `phonekey` user; pam_phonekey.so and the CLI connect to /run/phonekey/.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import pwd
import signal
import socket
import stat
import struct
import sys
from pathlib import Path
from typing import Callable

from . import command, crypto, presence
from .core import DaemonCore, Event
from .paths import default_socket_path, default_state_dir
from .registry import Registry
from .verifier import Verifier

log = logging.getLogger("phonekeyd")

MAX_REQUEST = 4096
MAX_CLIENTS = 64         # simultaneous local connections, all users together
MAX_CLIENTS_PER_UID = 8  # so one local user cannot starve the others (or PAM, uid 0)
CLIENT_IDLE_TIMEOUT = 10  # seconds to send a request after connecting
PAIRING_WINDOW = 120.0
# The phone displays these; clients pick one, they cannot supply free text.
ACTIONS = {"test": "phonekey.test", "sudo": "linux.sudo", "unlock": "linux.unlock", "login": "linux.login"}
# Actions that reach the phone only for someone at this computer (presence.py, SECURITY.md D-15).
LOCAL_ONLY = {"linux.sudo"}


def peer_cred(sock: socket.socket) -> tuple[int, int]:
    """(pid, uid) of the process that connected."""
    pid, uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                         struct.calcsize("3i")))
    return pid, uid


def authorize(op: str, uid: int, account: str | None, *, daemon_uid: int, system_mode: bool,
              action: str | None = None) -> str | None:
    """Returns None if allowed, else the reason. See SECURITY.md §4."""
    if op == "status":
        return None
    if op == "pair":
        if system_mode:
            return None if uid == 0 else "pairing requires root (sudo phonekey pair)"
        if uid != daemon_uid:
            return "not allowed"
        return None if account in (None, _user_name(uid)) else "may only pair your own account"
    if op == "auth":
        if uid == 0:
            return None
        if action == "sudo":
            return "sudo approvals may only come from sudo (root)"
        try:
            name = pwd.getpwuid(uid).pw_name
        except KeyError:
            return "unknown caller"
        return None if account == name else "may only authenticate your own account"
    return "unknown operation"


def parse_request(line: bytes) -> dict:
    """One JSON object with string `op` and optional string `account`/`action`. Raises ValueError."""
    try:
        request = json.loads(line)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("not JSON") from None
    if not isinstance(request, dict) or not isinstance(request.get("op"), str):
        raise ValueError("not a request")
    for key in ("account", "action"):
        if key in request and not isinstance(request[key], str):
            raise ValueError(f"{key} must be a string")
    return request


def _user_name(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def pairable_account(account) -> str | None:
    """A phone can be paired to an existing, non-root login account."""
    if not isinstance(account, str):
        return "bad account"
    try:
        entry = pwd.getpwnam(account)
    except KeyError:
        return f"no such account: {account}"
    if entry.pw_uid == 0:
        return "pair a normal account, not root"
    return None


class Client:
    def __init__(self, server: IpcServer, sock: socket.socket):
        from gi.repository import GLib

        self.server, self.sock = server, sock
        self.pid, self.uid = peer_cred(sock)
        self.buffer = b""
        self.closed = False
        self.on_close = None
        self.on_line = None  # follow-up lines after the request (pairing confirmation)
        self._watch = GLib.io_add_watch(sock.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self._readable)
        self._idle = GLib.timeout_add_seconds(CLIENT_IDLE_TIMEOUT, self._idle_timeout)

    def _idle_timeout(self):
        self._idle = None
        if not self.closed and self.buffer is not None:
            self.close()
        return False

    def _readable(self, fd, condition):
        try:
            data = self.sock.recv(MAX_REQUEST)
        except OSError:
            data = b""
        if not data:
            self.close()
            return False
        if self.buffer is None:  # request already received
            if self.on_line is not None:
                self.pending_lines = getattr(self, "pending_lines", b"") + data
                while b"\n" in self.pending_lines:
                    line, self.pending_lines = self.pending_lines.split(b"\n", 1)
                    self.on_line(line)
                if len(self.pending_lines) > MAX_REQUEST:
                    self.close()
                    return False
            return True
        self.buffer += data
        if b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)[0], None
            self._cancel_idle()
            self.server.handle(self, line)
        elif len(self.buffer) > MAX_REQUEST:
            self.close()
            return False
        return True

    def _cancel_idle(self):
        from gi.repository import GLib

        if self._idle is not None:
            GLib.source_remove(self._idle)
            self._idle = None

    def send(self, event: Event, final: bool = False) -> None:
        if self.closed:
            return
        try:
            self.sock.sendall(json.dumps(event).encode() + b"\n")
        except OSError:
            self.close()
            return
        if final:
            self.close()

    def close(self) -> None:
        from gi.repository import GLib

        if self.closed:
            return
        self.closed = True
        self.server.forget(self)
        self._cancel_idle()
        GLib.source_remove(self._watch)
        self.sock.close()
        if self.on_close:
            self.on_close()


class IpcServer:
    def __init__(self, path: Path, core: DaemonCore, *, system_mode: bool, hostname: str,
                 presence_check: Callable[[int, str], str | None]):
        self.path, self.core, self.system_mode, self.hostname = path, core, system_mode, hostname
        self.presence_check = presence_check
        self.clients: set[Client] = set()
        self.daemon_uid = os.getuid()
        self.sock: socket.socket | None = None

    def start(self) -> None:
        from gi.repository import GLib

        self.path.parent.mkdir(mode=0o700 if not self.system_mode else 0o755, parents=True, exist_ok=True)
        if self.path.exists() or self.path.is_symlink():
            if not stat.S_ISSOCK(os.lstat(self.path).st_mode):
                raise RuntimeError(f"{self.path} exists and is not a socket")
            self.path.unlink()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(self.path))
        os.chmod(self.path, 0o666 if self.system_mode else 0o600)  # authorization is by SO_PEERCRED
        self.sock.listen(8)
        GLib.io_add_watch(self.sock.fileno(), GLib.IO_IN, self._accept)
        log.info("listening on %s", self.path)

    def stop(self) -> None:
        if self.sock is not None:
            self.sock.close()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass

    def _accept(self, fd, condition):
        try:
            conn, _ = self.sock.accept()
        except OSError as e:  # e.g. out of file descriptors: keep serving the others
            log.warning("accept failed: %s", e)
            return True
        _pid, uid = peer_cred(conn)
        same_uid = sum(1 for c in self.clients if c.uid == uid)
        if len(self.clients) >= MAX_CLIENTS or same_uid >= MAX_CLIENTS_PER_UID:
            log.warning("too many connections (uid %d); refusing one", uid)
            conn.close()
            return True
        client = Client(self, conn)
        self.clients.add(client)
        return True

    def forget(self, client: Client) -> None:
        self.clients.discard(client)

    def handle(self, client: Client, line: bytes) -> None:
        try:
            request = parse_request(line)
        except ValueError:
            client.send({"result": "error", "reason": "bad request"}, final=True)
            return
        try:
            self._handle(client, request)
        except Exception:  # never leave a caller (e.g. sudo) waiting on a half-handled request
            log.exception("error handling %s request", request["op"])
            client.send({"result": "error", "reason": "internal error"}, final=True)

    def _handle(self, client: Client, request: dict) -> None:
        op = request["op"]
        account = request.get("account")
        reason = authorize(op, client.uid, account, daemon_uid=self.daemon_uid, system_mode=self.system_mode,
                           action=request.get("action"))
        if reason is not None:
            log.warning("refused %s from uid %d: %s", op, client.uid, reason)
            client.send({"result": "error", "reason": reason}, final=True)
            return

        if op == "status":
            status = self.core.status()
            if client.uid not in (0, self.daemon_uid):  # other users see only their own phones
                name = _user_name(client.uid)
                status["paired"] = [d for d in status["paired"] if d["account"] == name]
            client.send({"result": "ok", "mode": "system" if self.system_mode else "development", **status},
                        final=True)
        elif op == "pair":
            pair_account = account or pwd.getpwuid(client.uid).pw_name
            reason = pairable_account(pair_account)
            if reason is not None:
                client.send({"result": "error", "reason": reason}, final=True)
                return
            client.on_close = self.core.cancel_pairing  # Ctrl-C in the CLI ends the window
            client.on_line = self._pairing_answer
            self.core.start_pairing(pair_account, PAIRING_WINDOW,
                                    lambda e: self._forward(client, e))
        elif op == "auth":
            action = ACTIONS.get(request.get("action", ""))
            if action is None:
                client.send({"result": "error", "reason": "unknown action"}, final=True)
                return
            if action in LOCAL_ONLY:
                reason = self.presence_check(client.pid, account)
                if reason is not None:
                    log.info("auth request not sent to the phone: %s (%s)", action, reason)
                    client.send({"result": "unavailable", "reason": f"not local: {reason}"}, final=True)
                    return
            # The phone shows the sudo command; read by us from the caller's process, never sent by it.
            detail = command.sudo_command(client.pid) if action == "linux.sudo" and client.uid == 0 else None
            log.info("auth request: account=%s action=%s%s", account, action, " (with command)" if detail else "")
            self.core.authenticate(account, action, self.hostname, lambda e: self._forward(client, e), detail)

    def _pairing_answer(self, line: bytes) -> None:
        try:
            accepted = json.loads(line).get("confirm") is True
        except (ValueError, AttributeError):
            accepted = False
        self.core.answer_bond_confirmation(accepted)

    @staticmethod
    def _forward(client: Client, event: Event) -> None:
        final = "result" in event
        if final:
            client.on_close = None
            log.info("result: %s", {k: v for k, v in event.items() if k in ("result", "reason")})
        client.send(event, final=final)


class GLibScheduler:
    def call_later(self, seconds, callback):
        from gi.repository import GLib

        def fire():
            callback()
            return False

        return GLib.timeout_add(int(seconds * 1000), fire)

    def cancel(self, handle):
        from gi.repository import GLib

        GLib.source_remove(handle)


class _Transport:
    """Late-bound BLE transport for DaemonCore."""

    central = None

    def send(self, peer_id, frame):
        self.central.send(peer_id, frame)

    def set_pairing_mode(self, enabled):
        self.central.set_pairing_mode(enabled)

    def drop(self, peer_id):
        self.central.drop(peer_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phonekeyd", description="PhoneKey BLE verifier daemon (pre-alpha).")
    parser.add_argument("--system", action="store_true",
                        help="system service mode: /var/lib/phonekey, /run/phonekey, pairing needs root")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--socket", type=Path)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    args.state_dir = args.state_dir or default_state_dir(system=args.system)
    args.socket = args.socket or default_socket_path(system=args.system)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    import dbus
    import dbus.mainloop.glib
    from gi.repository import GLib

    from .ble import BleCentral, find_adapter

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    adapter = find_adapter(bus)
    if adapter is None:
        log.error("no Bluetooth adapter found (systemd retries in a few seconds)")
        return 1

    hostname = socket.gethostname()
    os.umask(0o077)
    key = crypto.load_or_create_key(args.state_dir / "verifier_key.pem")
    verifier = Verifier(key, Registry(args.state_dir), display_name=hostname)
    transport = _Transport()
    core = DaemonCore(verifier, transport, GLibScheduler())
    transport.central = BleCentral(bus, adapter, core.on_connect, core.on_frame, core.on_disconnect,
                                   core.on_bond_confirmation)
    ipc = IpcServer(args.socket, core, system_mode=args.system, hostname=hostname,
                    presence_check=presence.checker(presence.Logind(bus)))
    loop = GLib.MainLoop()
    log.info("verifier %s (%s), state %s", verifier.verifier_id[:4].hex(), hostname, args.state_dir)

    def shutdown(*_):
        log.info("shutting down")
        transport.central.stop()
        ipc.stop()
        loop.quit()
        return False

    exit_code = 0

    def failed(reason):
        nonlocal exit_code
        log.error(reason)
        exit_code = 1  # non-zero, so systemd's Restart=on-failure brings us back
        shutdown()

    for sig in (signal.SIGINT, signal.SIGTERM):
        GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, shutdown)
    ipc.start()
    transport.central.start(on_ready=lambda: log.info("ready"), on_error=failed)
    loop.run()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
