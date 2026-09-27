"""`phonekey` command-line interface (Phase 2: no daemon, no BLE, no PAM)."""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys
import tempfile
from pathlib import Path

from . import __version__, codec, crypto
from .codec import MsgType
from .paths import default_socket_path, default_state_dir, dev_socket_path
from .registry import DeviceRecord, Registry
from .simulator import SimulatedAuthenticator
from .verifier import Verifier


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


class DaemonUnavailable(Exception):
    pass


def daemon_request(request: dict, timeout: float = 150.0, replies: list | None = None):
    """Sends one request to phonekeyd and yields its JSON events until the final result.

    Anything appended to `replies` while handling an event is sent back as a JSON line.
    """
    import json

    candidates = [default_socket_path(system=True), dev_socket_path()] if "PHONEKEY_SOCKET" not in os.environ \
        else [default_socket_path()]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    for path in candidates:
        try:
            sock.connect(str(path))
            break
        except OSError:
            continue
    else:
        sock.close()
        raise DaemonUnavailable("phonekeyd is not running (start it with linux/cli/phonekeyd)")
    with sock, sock.makefile("rb") as stream:
        sock.sendall(json.dumps(request).encode() + b"\n")
        for line in stream:
            event = json.loads(line)
            yield event
            if "result" in event:
                return
            while replies:
                sock.sendall(json.dumps(replies.pop(0)).encode() + b"\n")
    raise DaemonUnavailable("phonekeyd closed the connection")


def daemon_status() -> dict | None:
    try:
        return next(e for e in daemon_request({"op": "status"}, timeout=5) if "result" in e)
    except (DaemonUnavailable, OSError, StopIteration, ValueError):
        return None


def fingerprint(device_id: bytes) -> str:
    h = device_id[:8].hex()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def describe(record: DeviceRecord) -> str:
    return (f"{record.display_name}  [{fingerprint(record.device_id)}]  account={record.account}  "
            f"key={record.key_security.name}  attestation={record.attestation}  paired={record.paired_at}")


def cmd_status(args: argparse.Namespace) -> int:
    devices = Registry(args.state_dir).all()
    daemon = daemon_status()
    connected = {d["device_id"] for d in daemon["paired"] if d["connected"]} if daemon else set()
    print("PhoneKey")
    print("--------")
    print(f"PhoneKey daemon: {'running (' + daemon['mode'] + ' mode)' if daemon else 'not running'}")
    print(f"Bluetooth: {bluetooth_state()}")
    print(f"Paired devices: {len(devices)}")
    for record in devices:
        state = "connected" if record.device_id.hex() in connected else "not connected"
        print(f"Device: {record.display_name} [{fingerprint(record.device_id)}] — {state}")
    ready = daemon is not None and bool(connected)
    print("Authentication: " + ("ready" if ready else "not ready"))
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
    if args.simulate:
        return run_simulation()
    try:
        for event in daemon_request({"op": "auth", "action": "test", "account": getpass.getuser()}):
            if event.get("event") == "sent":
                print(f"Phone detected: {event['device']}")
                print("Authentication request sent.")
                print("Authenticate on Android...")
            elif event["result"] == "ok":
                print()
                print("✓ Biometric authentication successful")
                print("✓ Signature verified")
                print("✓ PhoneKey authentication successful")
                return 0
            else:
                print(f"✗ PhoneKey authentication failed: {event['result']} ({event.get('reason', '')})")
                return 1
    except DaemonUnavailable as e:
        print(f"phonekey: {e}", file=sys.stderr)
        return 2
    return 1


def cmd_pair(args: argparse.Namespace) -> int:
    replies: list = []
    try:
        for event in daemon_request({"op": "pair"}, replies=replies):
            if event.get("event") == "waiting":
                print(f"Pairing mode is open for {int(event['window'])} seconds.")
                print("On your phone: open PhoneKey → Add computer.")
                print("Waiting for the phone... (Ctrl-C to cancel)")
            elif event.get("event") == "confirm":
                code = event["passkey"]
                print()
                print(f"Bluetooth pairing code:  {code[:3]} {code[3:]}")
                answer = input("Does your phone show exactly the same code? [y/N] ").strip().lower()
                replies.append({"confirm": answer in ("y", "yes")})
                print("Now confirm on the phone too, then approve the computer in PhoneKey." if answer in ("y", "yes")
                      else "Rejected.")
            elif event["result"] == "paired":
                print()
                print(f"✓ Paired {event['name']} [{fingerprint(bytes.fromhex(event['device_id']))}]")
                print(f"  Key protection: {event['key_security']}   Attestation: {event['attestation']}")
                return 0
            else:
                print(f"✗ Pairing failed: {event.get('reason', event['result'])}")
                return 1
    except DaemonUnavailable as e:
        print(f"phonekey: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nPairing cancelled.")
        return 130
    return 1


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
        checks.append(("unknown phone rejected", verifier.complete_auth(forge_response(message, phone.device_id))))

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


def forge_response(request: bytes, device_id: bytes) -> bytes:
    """A stranger's key answering a request while claiming to be the paired device."""
    msg = codec.decode(request)
    unsigned = codec.encode_unsigned(MsgType.AUTH_RESPONSE, {
        "verifier_id": msg["verifier_id"], "device_id": device_id,
        "request_id": msg["request_id"], "request_hash": crypto.sha256(request),
    })
    return codec.with_signature(unsigned, crypto.sign(crypto.generate_key(), crypto.LABEL_AUTH_ASSERTION, unsigned))


def cmd_logs(args: argparse.Namespace) -> int:
    """The system service logs to the journal; the development daemon logs to its terminal."""
    if subprocess_run(["systemctl", "is-active", "--quiet", "phonekeyd"]) == 0:
        return subprocess_run(["journalctl", "-u", "phonekeyd", "-n", str(args.lines), "--no-pager"]
                              + (["-f"] if args.follow else []))
    print("phonekeyd is not installed as a service. The development daemon (linux/cli/phonekeyd)\n"
          "logs to the terminal it runs in.")
    return 0


def subprocess_run(argv: list[str]) -> int:
    import subprocess

    try:
        return subprocess.run(argv).returncode
    except FileNotFoundError:
        return 127


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

    sub.add_parser("pair", help="pair a phone over Bluetooth (needs phonekeyd)").set_defaults(func=cmd_pair)

    logs = sub.add_parser("logs", help="show daemon logs")
    logs.add_argument("-n", "--lines", type=int, default=50)
    logs.add_argument("-f", "--follow", action="store_true")
    logs.set_defaults(func=cmd_logs)

    test = sub.add_parser("test", help="run an end-to-end authentication test")
    test.add_argument("--simulate", action="store_true",
                      help="use an in-memory software authenticator instead of a phone")
    test.set_defaults(func=cmd_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
