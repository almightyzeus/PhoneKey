"""`phonekey` command-line interface (Phase 2: no daemon, no BLE, no PAM)."""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys
import tempfile
from pathlib import Path

from . import __version__, crypto
from .registry import DeviceRecord, Registry
from .simulator import SimulatedAuthenticator
from .verifier import Verifier


def default_state_dir() -> Path:
    """Development state location; the system daemon will use /var/lib/phonekey (Phase 3)."""
    if "PHONEKEY_STATE_DIR" in os.environ:
        return Path(os.environ["PHONEKEY_STATE_DIR"])
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "phonekey-dev"


def bluetooth_state() -> str:
    """Read-only BlueZ query over D-Bus: is there a powered adapter?"""
    try:
        import dbus

        bus = dbus.SystemBus()
        manager = dbus.Interface(bus.get_object("org.bluez", "/"), "org.freedesktop.DBus.ObjectManager")
        adapters = [
            (path, ifaces["org.bluez.Adapter1"])
            for path, ifaces in manager.GetManagedObjects().items()
            if "org.bluez.Adapter1" in ifaces
        ]
    except Exception:
        return "unavailable"
    if not adapters:
        return "no adapter"
    path, props = adapters[0]
    name = str(path).rsplit("/", 1)[-1]
    return f"available ({name})" if props.get("Powered") else f"adapter off ({name})"


def fingerprint(device_id: bytes) -> str:
    h = device_id[:8].hex()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def describe(record: DeviceRecord) -> str:
    return (f"{record.display_name}  [{fingerprint(record.device_id)}]  account={record.account}  "
            f"key={record.key_security.name}  attestation={record.attestation}  paired={record.paired_at}")


def cmd_status(args: argparse.Namespace) -> int:
    devices = Registry(args.state_dir).all()
    print("PhoneKey")
    print("--------")
    print("PhoneKey daemon: not installed (arrives in Phase 3)")
    print(f"Bluetooth: {bluetooth_state()}")
    print(f"Paired devices: {len(devices)}")
    for record in devices:
        print(f"Device: {record.display_name} [{fingerprint(record.device_id)}]")
    print("Authentication: " + ("ready" if devices else "not ready (no paired device)"))
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    devices = Registry(args.state_dir).all()
    if not devices:
        print("No paired devices.")
    for record in devices:
        print(describe(record))
    return 0


def cmd_unpair(args: argparse.Namespace) -> int:
    registry = Registry(args.state_dir)
    if args.all:
        records = registry.all()
    else:
        try:
            records = [registry.find(args.device)]
        except (ValueError, LookupError) as e:
            print(f"phonekey: {e}", file=sys.stderr)
            return 1
    for record in records:
        registry.remove(record.device_id)
        print(f"Unpaired {record.display_name} [{fingerprint(record.device_id)}]")
    if not records:
        print("No paired devices.")
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    if not args.simulate:
        print("phonekey: talking to a real phone needs the BLE transport (Phase 3).\n"
              "Run `phonekey test --simulate` to exercise the protocol with a software authenticator.",
              file=sys.stderr)
        return 2
    return run_simulation()


def run_simulation() -> int:
    """Full pairing + authentication against an in-memory authenticator.

    Uses a throwaway registry and verifier key in a temporary directory, so a
    software key can never end up in the real registry.
    """
    account, host = getpass.getuser(), socket.gethostname()
    with tempfile.TemporaryDirectory(prefix="phonekey-sim-") as tmp:
        verifier = Verifier(crypto.generate_key(), Registry(Path(tmp)), display_name=host,
                            allow_software_keys=True)
        phone = SimulatedAuthenticator()
        record = verifier.complete_pairing(phone.handle_pair_request(verifier.begin_pairing(account=account)))

        print("PhoneKey — simulated authenticator (no Bluetooth, temporary registry)")
        print("--------")
        print(f"Bluetooth: {bluetooth_state()} (not used)")
        print(f"Paired device: {record.display_name} [{fingerprint(record.device_id)}]")
        print("Connection: simulated")
        print("Authentication: ready")
        print()

        def request() -> tuple[bytes, bytes]:
            return verifier.begin_auth(phone.device_id, account=account, action="phonekey.test", resource=host)

        print("Authentication request sent...")
        _, message = request()
        print("Waiting for biometric... (simulated approval)")
        response = phone.handle_auth_request(message)
        result = verifier.complete_auth(response)
        if not result.ok:
            print(f"✗ Authentication failed: {result.error.name}")
            return 1
        print("✓ Signature verified")
        print("✓ PhoneKey authentication successful")
        print()

        checks = [("replayed response rejected", verifier.complete_auth(response))]

        _, message = request()
        tampered = bytearray(phone.handle_auth_request(message))
        tampered[-1] ^= 0x01
        checks.append(("tampered signature rejected", verifier.complete_auth(bytes(tampered))))

        _, message = request()
        altered = bytearray(message)
        altered[altered.index(b"phonekey.test")] ^= 0x01  # attacker edits the action in flight
        reply = phone.handle_auth_request(bytes(altered))  # phone refuses: bad verifier signature
        checks.append(("modified request rejected", verifier.complete_auth(reply)))

        _, message = request()
        stranger = SimulatedAuthenticator("Unknown phone")
        stranger.handle_pair_request(verifier.begin_pairing(account=account))  # stranger knows the verifier...
        checks.append(("unknown phone rejected", verifier.complete_auth(stranger.handle_auth_request(message))))

        _, message = request()
        checks.append(("user denial rejected", verifier.complete_auth(phone.handle_auth_request(message, approve=False))))

        print("Security checks:")
        passed = True
        for name, outcome in checks:
            ok = not outcome.ok
            passed &= ok
            detail = outcome.error.name if outcome.error else "ACCEPTED"
            print(f"{'✓' if ok else '✗'} {name} ({detail})")
        return 0 if passed else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phonekey", description="PhoneKey verifier tools (pre-alpha).")
    parser.add_argument("--version", action="version", version=f"phonekey {__version__}")
    parser.add_argument("--state-dir", type=Path, default=default_state_dir(),
                        help="registry location (default: %(default)s)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show Bluetooth and pairing status").set_defaults(func=cmd_status)
    sub.add_parser("devices", help="list paired devices").set_defaults(func=cmd_devices)

    unpair = sub.add_parser("unpair", help="revoke a paired device (works without the phone)")
    target = unpair.add_mutually_exclusive_group(required=True)
    target.add_argument("device", nargs="?", help="device id prefix (see `phonekey devices`)")
    target.add_argument("--all", action="store_true", help="revoke every paired device")
    unpair.set_defaults(func=cmd_unpair)

    test = sub.add_parser("test", help="run an end-to-end authentication test")
    test.add_argument("--simulate", action="store_true",
                      help="use an in-memory software authenticator instead of a phone")
    test.set_defaults(func=cmd_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
