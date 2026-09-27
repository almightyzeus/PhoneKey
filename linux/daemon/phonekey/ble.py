"""BlueZ central: finds PhoneKey phones, connects, and exchanges frames (PROTOCOL.md §6.1).

The laptop is the BLE central and never advertises. Only phones that are
already bonded, or that advertise the pairing UUID while a pairing window is
open, are connected. During a pairing window a BlueZ agent is registered (never
as the default agent), so BlueZ asks *us* to confirm the numeric comparison for
pairings this process starts; every other pairing method is rejected.
"""

from __future__ import annotations

import collections
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

import dbus
import dbus.exceptions
import dbus.service

log = logging.getLogger(__name__)

SERVICE_UUID = "eb109ed5-92be-4d34-a98d-61bb7f350b41"
A2V_UUID = "f3c11509-8693-4342-ae5b-8d0f7e6e50fa"  # authenticator → verifier (indicate)
V2A_UUID = "955060b9-442a-41f4-bea8-251ea1f42f85"  # verifier → authenticator (write)
PAIRING_ADV_UUID = "419b7d95-95a6-441f-a103-eb24d90499e0"

BLUEZ = "org.bluez"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
GATT_CHRC = "org.bluez.GattCharacteristic1"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
PROPERTIES = "org.freedesktop.DBus.Properties"

AGENT_MANAGER = "org.bluez.AgentManager1"
AGENT = "org.bluez.Agent1"
AGENT_PATH = "/dev/phonekey/agent"

RETRY_COOLDOWN = 10.0  # seconds before retrying a device whose connection failed

Confirm = Callable[[str, int, Callable[[bool], None]], None]


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


def find_adapter(bus: dbus.Bus) -> str | None:
    manager = dbus.Interface(bus.get_object(BLUEZ, "/"), OBJECT_MANAGER)
    for path, ifaces in manager.GetManagedObjects().items():
        if ADAPTER in ifaces:
            return str(path)
    return None


@dataclass
class _Link:
    pairing: bool
    bonded: bool = False  # never touch protected attributes before bonding completes
    notify_path: str | None = None
    write_path: str | None = None
    mtu: int | None = None
    ready: bool = False
    queue: collections.deque = field(default_factory=collections.deque)
    writing: bool = False


class BleCentral:
    def __init__(self, bus: dbus.Bus, adapter_path: str,
                 on_connect: Callable[[str, int | None], None],
                 on_frame: Callable[[str, bytes, int | None], None],
                 on_disconnect: Callable[[str], None],
                 on_confirm: Confirm):
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
        self._bus.add_signal_receiver(self._characteristic_changed, dbus_interface=PROPERTIES,
                                      signal_name="PropertiesChanged", arg0=GATT_CHRC, path_keyword="path")
        try:
            self._adapter.SetDiscoveryFilter({
                "Transport": "le",
                "UUIDs": dbus.Array([SERVICE_UUID, PAIRING_ADV_UUID], signature="s"),
                "DuplicateData": dbus.Boolean(True),
            })
            self._adapter.StartDiscovery()
        except dbus.exceptions.DBusException as e:
            on_error(f"cannot start LE discovery: {e.get_dbus_message()}")
            return
        log.info("scanning for PhoneKey phones")
        for path, ifaces in self._managed_objects().items():
            if DEVICE in ifaces:
                self._consider(str(path), ifaces[DEVICE])
        on_ready()

    def stop(self) -> None:
        if self._agent_registered:
            self.set_pairing_mode(False)
        try:
            self._adapter.StopDiscovery()
        except dbus.exceptions.DBusException:
            pass
        for path in list(self._links):
            self._disconnect(path)

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
        link.queue.append(frame)
        self._pump(peer_id, link)

    # ---- discovery and connection ---------------------------------------

    def _managed_objects(self) -> dict:
        return dbus.Interface(self._bus.get_object(BLUEZ, "/"), OBJECT_MANAGER).GetManagedObjects()

    def _device(self, path: str) -> dbus.Interface:
        return dbus.Interface(self._bus.get_object(BLUEZ, path), DEVICE)

    def _interfaces_added(self, path, ifaces):
        if DEVICE in ifaces:
            self._consider(str(path), ifaces[DEVICE])

    def _device_changed(self, interface, changed, invalidated, path=None):
        path = str(path)
        if not path.startswith(self._adapter_path + "/"):
            return
        if "Connected" in changed and not changed["Connected"]:
            if self._links.pop(path, None) is not None:
                log.info("disconnected %s", path)
                self._on_disconnect(path)
            return
        if path in self._links:
            if changed.get("ServicesResolved") and self._links[path].bonded:
                self._setup_gatt(path, final=True)
            return
        if {"UUIDs", "RSSI", "ServiceData"} & set(changed):
            props = dbus.Interface(self._bus.get_object(BLUEZ, path), PROPERTIES).GetAll(DEVICE)
            self._consider(path, props)

    def _consider(self, path: str, props) -> None:
        if path in self._links or time.monotonic() < self._cooldown.get(path, 0):
            return
        if props.get("RSSI") is None and not props.get("Connected"):
            return  # not advertising right now (only cached by BlueZ): connecting would just time out
        uuids = {str(u).lower() for u in props.get("UUIDs", [])}
        pairing_busy = any(link.pairing for link in self._links.values())
        if self._pairing and PAIRING_ADV_UUID in uuids and not pairing_busy:
            self._connect(path, pairing=True, bonded=bool(props.get("Paired")))
        elif SERVICE_UUID in uuids and props.get("Paired"):
            self._connect(path, pairing=False, bonded=True)

    def _connect(self, path: str, *, pairing: bool, bonded: bool) -> None:
        link = _Link(pairing=pairing, bonded=bonded)
        self._links[path] = link
        log.info("connecting to %s (%s)", path, "pairing" if pairing else "bonded")

        def bonded_ok():
            link.bonded = True
            log.info("bonded with %s", path)
            self._maybe_resolved(path)

        def connected():
            if bonded:
                self._maybe_resolved(path)
                return
            # Subscribing before this finishes would start a second, competing security procedure.
            log.info("bonding with %s: confirm the code on the phone and in the laptop's Bluetooth dialog", path)
            self._device(path).Pair(reply_handler=bonded_ok,
                                    error_handler=lambda e: self._fail(path, f"bonding failed: {e}"),
                                    timeout=90)

        def connect_error(e):
            # For a bonded dual-mode phone, Connect() also tries classic-Bluetooth profiles
            # and reports their failure (br-connection-*) even though the LE link is up.
            props = dbus.Interface(self._bus.get_object(BLUEZ, path), PROPERTIES).GetAll(DEVICE)
            if props.get("Connected") and path in self._links:
                log.info("LE link to %s is up (ignoring: %s)", path, e.get_dbus_message())
                connected()
            else:
                self._fail(path, f"connect failed: {e}")

        self._device(path).Connect(reply_handler=connected, error_handler=connect_error, timeout=15)

    def _maybe_resolved(self, path: str) -> None:
        # Bonded phones usually have a cached GATT database; ServicesResolved can stay
        # false when BlueZ's parallel classic-Bluetooth attempt fails, so don't rely on it.
        props = dbus.Interface(self._bus.get_object(BLUEZ, path), PROPERTIES).GetAll(DEVICE)
        self._setup_gatt(path, final=bool(props.get("ServicesResolved")))

    def _setup_gatt(self, path: str, final: bool) -> None:
        """Finds the PhoneKey characteristics and subscribes. If they are not there yet and
        services are still resolving (not `final`), wait for the ServicesResolved signal."""
        link = self._links.get(path)
        if link is None or link.notify_path is not None:
            return  # unknown, or already set up (ServicesResolved and Connect can both get here)
        for obj_path, ifaces in self._managed_objects().items():
            chrc = ifaces.get(GATT_CHRC)
            if chrc is None or not str(obj_path).startswith(path + "/"):
                continue
            uuid = str(chrc["UUID"]).lower()
            if uuid == A2V_UUID:
                link.notify_path = str(obj_path)
                link.mtu = int(chrc["MTU"]) if "MTU" in chrc else None
            elif uuid == V2A_UUID:
                link.write_path = str(obj_path)
        if link.notify_path is None or link.write_path is None:
            link.notify_path = link.write_path = None
            if final:
                self._fail(path, "PhoneKey service not found on device")
            return
        chrc = dbus.Interface(self._bus.get_object(BLUEZ, link.notify_path), GATT_CHRC)
        chrc.StartNotify(reply_handler=lambda: self._ready(path),
                         error_handler=lambda e: self._fail(path, f"subscribe failed: {e}"))

    def _ready(self, path: str) -> None:
        link = self._links.get(path)
        if link is None:
            return
        link.ready = True
        log.info("subscribed to %s (ATT MTU %s)", path, link.mtu)
        self._on_connect(path, link.mtu)

    def _fail(self, path: str, reason: str) -> None:
        log.warning("%s: %s", path, reason)
        # BlueZ sometimes picks classic Bluetooth for a dual-mode phone; the next LE
        # advertisement makes it choose LE, so retry soon.
        quick = "br-connection" in reason
        self._cooldown[path] = time.monotonic() + (1.0 if quick else RETRY_COOLDOWN)
        self._disconnect(path)

    def _disconnect(self, path: str) -> None:
        if self._links.pop(path, None) is not None:
            self._on_disconnect(path)
        try:
            self._device(path).Disconnect(reply_handler=lambda: None, error_handler=lambda e: None)
        except dbus.exceptions.DBusException:
            pass

    # ---- data ------------------------------------------------------------

    def _characteristic_changed(self, interface, changed, invalidated, path=None):
        if "Value" not in changed:
            return
        path = str(path)
        device_path = path.rsplit("/", 2)[0]  # .../dev_XX/serviceNN/charNNNN
        link = self._links.get(device_path)
        if link is not None and link.ready and path == link.notify_path:
            self._on_frame(device_path, bytes(changed["Value"]), link.mtu)

    def _pump(self, peer_id: str, link: _Link) -> None:
        if link.writing or not link.queue:
            return
        link.writing = True
        frame = link.queue.popleft()

        def done():
            link.writing = False
            self._pump(peer_id, link)

        def failed(e):
            link.writing = False
            link.queue.clear()
            self._fail(peer_id, f"write failed: {e}")

        chrc = dbus.Interface(self._bus.get_object(BLUEZ, link.write_path), GATT_CHRC)
        chrc.WriteValue(dbus.Array(frame, signature="y"), {"type": "request"},
                        reply_handler=done, error_handler=failed)
