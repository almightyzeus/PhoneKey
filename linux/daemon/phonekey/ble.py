"""BLE central: finds PhoneKey phones and exchanges frames with them (PROTOCOL.md §6).

The laptop is the central and never advertises. Data goes over an L2CAP LE
socket that this process opens itself to the phone's ATT channel (see att.py),
not through BlueZ's Device1.Connect: for a dual-mode phone BlueZ often picks
classic Bluetooth and may try audio/phonebook profiles, which PhoneKey must
never do. The socket requires the authenticated, encrypted bond.

BlueZ is still used for LE scanning and for the one-time bonding. During a
pairing window a BlueZ agent is registered (never as the default agent), so
BlueZ asks *us* to confirm the numeric comparison for pairings this process
starts; every other pairing method is rejected.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Callable

import dbus
import dbus.exceptions
import dbus.service

from .att import AttClient, AttError

log = logging.getLogger(__name__)

SERVICE_UUID = "eb109ed5-92be-4d34-a98d-61bb7f350b41"
A2V_UUID = "f3c11509-8693-4342-ae5b-8d0f7e6e50fa"  # authenticator → verifier (indicate)
V2A_UUID = "955060b9-442a-41f4-bea8-251ea1f42f85"  # verifier → authenticator (write)
PAIRING_ADV_UUID = "419b7d95-95a6-441f-a103-eb24d90499e0"

BLUEZ = "org.bluez"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPERTIES = "org.freedesktop.DBus.Properties"
AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
AGENT_PATH = "/dev/phonekey/agent"

RETRY_COOLDOWN = 10.0  # seconds before retrying a device whose connection failed
QUICK_RETRY = 1.0
CONNECT_TIMEOUT = 20  # seconds for the LE connection and ATT setup
DISCOVERY_WATCHDOG = 5  # seconds between checks that our LE scan is still running

# Linux Bluetooth socket constants (include/net/bluetooth/bluetooth.h, l2cap.h)
SOL_BLUETOOTH = 274
BT_SECURITY = 4
BT_SECURITY_HIGH = 3  # encrypted with an authenticated (MITM-protected) key
ATT_CID = 4
BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM = 1, 2

Confirm = Callable[[str, int, Callable[[bool], None]], None]

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


class _SockaddrL2(ctypes.Structure):
    _fields_ = [("l2_family", ctypes.c_ushort), ("l2_psm", ctypes.c_ushort), ("l2_bdaddr", ctypes.c_ubyte * 6),
                ("l2_cid", ctypes.c_ushort), ("l2_bdaddr_type", ctypes.c_ubyte)]


def _sockaddr(address: str | None, address_type: int) -> _SockaddrL2:
    addr = _SockaddrL2()
    addr.l2_family = socket.AF_BLUETOOTH
    addr.l2_cid = ATT_CID
    addr.l2_bdaddr_type = address_type
    if address:
        addr.l2_bdaddr[:] = bytes(int(x, 16) for x in reversed(address.split(":")))
    return addr


def open_le_att_socket(address: str, address_type: int) -> socket.socket:
    """Starts a non-blocking LE connection to the peer's ATT channel (Python's socket
    module cannot express LE L2CAP addresses, hence ctypes)."""
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    try:
        sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack("BB", BT_SECURITY_HIGH, 0))
        local = _sockaddr(None, BDADDR_LE_PUBLIC)
        if _libc.bind(sock.fileno(), ctypes.byref(local), ctypes.sizeof(local)) != 0:
            raise OSError(ctypes.get_errno(), "bind: " + os.strerror(ctypes.get_errno()))
        sock.setblocking(False)
        remote = _sockaddr(address, address_type)
        if _libc.connect(sock.fileno(), ctypes.byref(remote), ctypes.sizeof(remote)) != 0:
            err = ctypes.get_errno()
            if err != errno.EINPROGRESS:
                raise OSError(err, "connect: " + os.strerror(err))
    except BaseException:
        sock.close()
        raise
    return sock


def find_adapter(bus: dbus.Bus) -> str | None:
    manager = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJECT_MANAGER)
    for path, ifaces in manager.GetManagedObjects().items():
        if ADAPTER in ifaces:
            return str(path)
    return None


class Rejected(dbus.exceptions.DBusException):
    _dbus_error_name = "org.bluez.Error.Rejected"


class PairingAgent(dbus.service.Object):
    """Accepts only LE Secure Connections numeric comparison, confirmed by the user."""

    def __init__(self, bus: dbus.Bus, confirm: Confirm):
        super().__init__(bus, AGENT_PATH)
        self._confirm = confirm

    @dbus.service.method(AGENT, in_signature="ou", out_signature="",
                         async_callbacks=("reply", "error"))
    def RequestConfirmation(self, device, passkey, reply, error):
        def answer(accepted: bool) -> None:
            reply() if accepted else error(Rejected("code not confirmed"))
        self._confirm(str(device), int(passkey), answer)

    @dbus.service.method(AGENT, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        raise Rejected("Just Works pairing is not allowed")  # no MITM protection

    @dbus.service.method(AGENT, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        raise Rejected("legacy pairing is not allowed")

    @dbus.service.method(AGENT, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        raise Rejected("passkey entry is not supported")

    @dbus.service.method(AGENT, in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device, passkey, entered):
        pass

    @dbus.service.method(AGENT, in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        raise Rejected("legacy pairing is not allowed")

    @dbus.service.method(AGENT, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        raise Rejected("not authorized")

    @dbus.service.method(AGENT, in_signature="", out_signature="")
    def Cancel(self):
        log.info("pairing request cancelled by BlueZ")

    @dbus.service.method(AGENT, in_signature="", out_signature="")
    def Release(self):
        pass


@dataclass
class _Link:
    pairing: bool
    sock: socket.socket | None = None
    client: AttClient | None = None
    connect_timer: int | None = None
    io_watch: int | None = None
    ready: bool = False


class BleCentral:
    def __init__(self, bus: dbus.Bus, adapter_path: str,
                 on_connect: Callable[[str, int | None], None],
                 on_frame: Callable[[str, bytes, int | None], None],
                 on_disconnect: Callable[[str], None],
                 on_confirm: Confirm):
        from gi.repository import GLib

        self._glib = GLib
        self._bus = bus
        self._adapter_path = adapter_path
        self._adapter = dbus.Interface(bus.get_object(BLUEZ, adapter_path), ADAPTER)
        self._on_connect, self._on_frame, self._on_disconnect = on_connect, on_frame, on_disconnect
        self._links: dict[str, _Link] = {}
        self._cooldown: dict[str, float] = {}
        self._pairing = False
        self._agent = PairingAgent(bus, on_confirm)
        self._agent_registered = False

    # ---- lifecycle -------------------------------------------------------

    def start(self, on_ready: Callable[[], None], on_error: Callable[[str], None]) -> None:
        self._bus.add_signal_receiver(self._interfaces_added, dbus_interface=OBJECT_MANAGER,
                                      signal_name="InterfacesAdded")
        self._bus.add_signal_receiver(self._device_changed, dbus_interface=PROPERTIES,
                                      signal_name="PropertiesChanged", arg0=DEVICE, path_keyword="path")
        try:
            self._start_discovery()
        except dbus.exceptions.DBusException as e:
            on_error(f"cannot start LE discovery: {e.get_dbus_message()}")
            return
        log.info("scanning for PhoneKey phones")
        self._glib.timeout_add_seconds(DISCOVERY_WATCHDOG, self._discovery_watchdog)
        on_ready()

    def _start_discovery(self) -> None:
        self._adapter.SetDiscoveryFilter({
            "Transport": "le",
            "UUIDs": dbus.Array([SERVICE_UUID, PAIRING_ADV_UUID], signature="s"),
            "DuplicateData": dbus.Boolean(True),
        })
        self._adapter.StartDiscovery()

    def _discovery_watchdog(self) -> bool:
        """BlueZ ends our scan when Bluetooth is toggled or devices are removed; restart it.

        Also follows the adapter when it disappears (a USB adapter that resets
        comes back as a new hciN)."""
        try:
            if self._adapter_path not in self._adapter_paths():
                self._switch_adapter()
                return True
            props = dbus.Interface(self._bus.get_object(BLUEZ, self._adapter_path), PROPERTIES)
            if props.Get(ADAPTER, "Powered") and not props.Get(ADAPTER, "Discovering"):
                self._start_discovery()
                log.info("scanning restarted")
        except dbus.exceptions.DBusException as e:
            log.debug("discovery watchdog: %s", e.get_dbus_message())
        return True

    def _adapter_paths(self) -> list[str]:
        return [str(p) for p, ifaces in self._managed_objects().items() if ADAPTER in ifaces]

    def _switch_adapter(self) -> None:
        paths = self._adapter_paths()
        log.warning("Bluetooth adapter %s is gone; %s", self._adapter_path,
                    f"switching to {paths[0]}" if paths else "waiting for one")
        for path in list(self._links):
            self._lost(path, "adapter removed")
        self._cooldown.clear()
        if not paths:
            return
        self._adapter_path = paths[0]
        self._adapter = dbus.Interface(self._bus.get_object(BLUEZ, self._adapter_path), ADAPTER)
        self._start_discovery()
        log.info("scanning for PhoneKey phones on %s", self._adapter_path)

    def stop(self) -> None:
        if self._agent_registered:
            self.set_pairing_mode(False)
        try:
            self._adapter.StopDiscovery()
        except dbus.exceptions.DBusException:
            pass
        for path in list(self._links):
            self._close(path)

    def set_pairing_mode(self, enabled: bool) -> None:
        self._pairing = enabled
        log.info("pairing window %s", "open" if enabled else "closed")
        agents = dbus.Interface(self._bus.get_object(BLUEZ, "/org/bluez"), AGENT_MANAGER)
        try:
            if enabled and not self._agent_registered:
                agents.RegisterAgent(AGENT_PATH, "DisplayYesNo")  # deliberately not RequestDefaultAgent
                self._agent_registered = True
            elif not enabled and self._agent_registered:
                agents.UnregisterAgent(AGENT_PATH)
                self._agent_registered = False
        except dbus.exceptions.DBusException as e:
            log.warning("pairing agent: %s", e.get_dbus_message())
        if enabled:
            self._cooldown.clear()
            for path, ifaces in self._managed_objects().items():
                if DEVICE in ifaces:
                    self._consider(str(path), ifaces[DEVICE])

    def send(self, peer_id: str, frame: bytes) -> None:
        link = self._links.get(peer_id)
        if link is None or not link.ready:
            log.info("dropping frame for %s: not connected", peer_id)
            return
        try:
            link.client.write(frame)
        except (AttError, OSError) as e:
            self._lost(peer_id, f"write failed: {e}")

    def drop(self, peer_id: str) -> None:
        """Disconnects a phone so it reconnects from scratch (the core already knows)."""
        self._close(peer_id)
        self._cooldown[peer_id] = time.monotonic() + QUICK_RETRY

    # ---- discovery ---------------------------------------------------------

    def _managed_objects(self) -> dict:
        return dbus.Interface(self._bus.get_object(BLUEZ, "/"), OBJECT_MANAGER).GetManagedObjects()

    def _device(self, path: str) -> dbus.Interface:
        return dbus.Interface(self._bus.get_object(BLUEZ, path), DEVICE)

    def _device_props(self, path: str) -> dict:
        return dbus.Interface(self._bus.get_object(BLUEZ, path), PROPERTIES).GetAll(DEVICE)

    def _interfaces_added(self, path, ifaces):
        if DEVICE in ifaces:
            self._consider(str(path), ifaces[DEVICE])

    def _device_changed(self, interface, changed, invalidated, path=None):
        path = str(path)
        if path.startswith(self._adapter_path + "/") and path not in self._links and \
                {"UUIDs", "RSSI", "ServiceData"} & set(changed):
            try:
                self._consider(path, self._device_props(path))
            except dbus.exceptions.DBusException:
                pass  # device removed meanwhile

    def _consider(self, path: str, props) -> None:
        if path in self._links or time.monotonic() < self._cooldown.get(path, 0):
            return
        if props.get("RSSI") is None:
            return  # not advertising right now (only cached by BlueZ)
        uuids = {str(u).lower() for u in props.get("UUIDs", [])}
        paired = bool(props.get("Paired"))
        pairing_busy = any(link.pairing for link in self._links.values())
        if self._pairing and PAIRING_ADV_UUID in uuids and not pairing_busy:
            self._links[path] = _Link(pairing=True)
            if paired:
                self._open(path)
            else:
                self._bond(path)
        elif SERVICE_UUID in uuids and paired:
            self._links[path] = _Link(pairing=False)
            self._open(path)

    # ---- one-time bonding through BlueZ ------------------------------------------

    def _bond(self, path: str) -> None:
        """Bonds via BlueZ (numeric comparison through our agent), then reconnects over our own socket."""
        log.info("bonding with %s: confirm the code in the terminal and on the phone", path)

        def reopen():
            if path in self._links:
                self._open(path)
            return False

        def bonded():
            log.info("bonded with %s", path)
            # BlueZ's link carries BlueZ's own ATT client; replace it with ours.
            self._device(path).Disconnect(reply_handler=lambda: self._glib.timeout_add(500, reopen),
                                          error_handler=lambda e: self._glib.timeout_add(500, reopen))

        def connected():
            self._device(path).Pair(reply_handler=bonded,
                                    error_handler=lambda e: self._fail(path, f"bonding failed: {e}"),
                                    timeout=90)

        # An unbonded phone advertises from a random address, so BlueZ connects over LE.
        self._device(path).Connect(reply_handler=connected,
                                   error_handler=lambda e: self._fail(path, f"connect failed: {e}"),
                                   timeout=CONNECT_TIMEOUT)

    # ---- our own LE ATT link ----------------------------------------------------

    def _open(self, path: str) -> None:
        link = self._links.get(path)
        if link is None:
            return
        props = self._device_props(path)
        address = str(props["Address"])
        address_type = BDADDR_LE_RANDOM if props.get("AddressType") == "random" else BDADDR_LE_PUBLIC
        log.info("connecting to %s over LE (%s)", path, "pairing" if link.pairing else "bonded")
        try:
            link.sock = open_le_att_socket(address, address_type)
        except OSError as e:
            self._fail(path, str(e))
            return
        GLib = self._glib
        link.connect_timer = GLib.timeout_add_seconds(CONNECT_TIMEOUT, self._connect_timeout, path)
        link.io_watch = GLib.io_add_watch(link.sock.fileno(), GLib.IO_OUT | GLib.IO_ERR | GLib.IO_HUP,
                                          self._socket_connected, path)

    def _connect_timeout(self, path: str) -> bool:
        link = self._links.get(path)
        if link is not None:
            link.connect_timer = None
            self._fail(path, "connection timed out")
        return False

    def _socket_connected(self, fd, condition, path: str) -> bool:
        link = self._links.get(path)
        if link is None or link.sock is None:
            return False
        link.io_watch = None
        err = link.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err:
            # Usually the phone's advertisement was not caught in time: retry soon.
            log.info("%s: LE connect failed: %s", path, os.strerror(err))
            self._cooldown[path] = time.monotonic() + QUICK_RETRY
            self._lost(path, None)
            return False
        sock = link.sock
        link.client = AttClient(
            SERVICE_UUID, A2V_UUID, V2A_UUID,
            send=sock.send,
            on_ready=lambda mtu: self._ready(path, mtu),
            on_value=lambda value: self._on_frame(path, value, link.client.mtu),
            on_error=lambda reason: self._fail(path, reason),
        )
        GLib = self._glib
        link.io_watch = GLib.io_add_watch(sock.fileno(), GLib.IO_IN | GLib.IO_ERR | GLib.IO_HUP,
                                          self._readable, path)
        link.client.start()
        return False

    def _readable(self, fd, condition, path: str) -> bool:
        link = self._links.get(path)
        if link is None or link.sock is None:
            return False
        try:
            pdu = link.sock.recv(1024)
        except BlockingIOError:
            return True
        except OSError as e:
            link.io_watch = None
            self._lost(path, f"link error: {e}")
            return False
        if not pdu:
            link.io_watch = None
            self._lost(path, "disconnected")
            return False
        link.client.feed(pdu)
        return True

    def _ready(self, path: str, mtu: int) -> None:
        link = self._links.get(path)
        if link is None:
            return
        if link.connect_timer is not None:
            self._glib.source_remove(link.connect_timer)
            link.connect_timer = None
        link.ready = True
        log.info("subscribed to %s over LE (ATT MTU %d)", path, mtu)
        self._on_connect(path, mtu)

    def _fail(self, path: str, reason: str) -> None:
        if path not in self._links:
            return
        log.warning("%s: %s", path, reason)
        self._cooldown[path] = time.monotonic() + RETRY_COOLDOWN
        self._lost(path, None)

    def _lost(self, path: str, reason: str | None) -> None:
        link = self._links.get(path)
        if link is None:
            return
        if reason:
            log.info("%s: %s", path, reason)
            self._cooldown.setdefault(path, time.monotonic() + QUICK_RETRY)
        was_ready = link.ready
        self._close(path)
        if was_ready:
            self._on_disconnect(path)

    def _close(self, path: str) -> None:
        link = self._links.pop(path, None)
        if link is None:
            return
        for source in (link.connect_timer, link.io_watch):
            if source is not None:
                self._glib.source_remove(source)
        if link.sock is not None:
            link.sock.close()
