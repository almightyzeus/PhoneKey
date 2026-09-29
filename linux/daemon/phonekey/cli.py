"""`phonekey` command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import socket
import sys
import tempfile
from pathlib import Path

from . import __version__, codec, crypto, pamconfig
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
    daemon = daemon_status()
    if daemon is not None:  # the daemon's own registry (unreadable to users in system mode)
        devices = [(d["name"], bytes.fromhex(d["device_id"]), d["connected"]) for d in daemon["paired"]]
    else:
        devices = [(r.display_name, r.device_id, False) for r in Registry(args.state_dir).all()]
    print("PhoneKey")
    print("--------")
    print(f"PhoneKey daemon: {'running (' + daemon['mode'] + ' mode)' if daemon else 'not running'}")
    print(f"Bluetooth: {bluetooth_state()}")
    print(f"Paired devices: {len(devices)}")
    for name, device_id, connected in devices:
        print(f"Device: {name} [{fingerprint(device_id)}] — {'connected' if connected else 'not connected'}")
    ready = any(connected for _, _, connected in devices)
    print("Authentication: " + ("ready" if ready else "not ready"))
    enabled = [p.name for p in pamconfig.enabled_files()] if pamconfig.PAM_DIR.is_dir() else []
    print("PAM: " + (f"enabled for {', '.join(enabled)}" if enabled else "not enabled (password only)"))
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


def target_user(args: argparse.Namespace) -> str:
    """The account being set up: --user, else the user who ran sudo, else the caller."""
    return getattr(args, "user", None) or os.environ.get("SUDO_USER") or getpass.getuser()


def cmd_pair(args: argparse.Namespace) -> int:
    replies: list = []
    account = target_user(args)
    if account == "root":
        print("phonekey: pair a normal account (run 'sudo phonekey pair' from it, or use --user)", file=sys.stderr)
        return 1
    print(f"Pairing a phone for account '{account}'.")
    try:
        for event in daemon_request({"op": "pair", "account": account}, replies=replies):
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


EFFECT = {
    "sudo": "Effect: sudo first asks your phone; if the phone is not connected, you deny, or it does\n"
            "not answer, sudo asks for your password as before. No other PAM file is changed.",
    "unlock": "Effect: waking the locked screen first asks your phone (\"PhoneKey: confirm on your\n"
              "phone\"). If the phone is not connected the password box appears at once; if you deny,\n"
              "or it does not answer within {timeout} s, the password box appears. No other PAM file is changed.",
}

RECOVERY = {
    "sudo": """\
If sudo misbehaves, the password still works: deny on the phone or wait {timeout} s.
To undo without sudo:   pkexec phonekey disable      (uses polkit, not /etc/pam.d/sudo)
Backups of the original file are in {backups}/.
Last resort: GRUB → Advanced options → recovery mode → root shell →
             mount -o remount,rw / && phonekey disable   (see protocol/SECURITY.md §9)""",
    "unlock": """\
If the lock screen misbehaves, the password still works: deny on the phone or wait {timeout} s.
If you cannot unlock at all (the text console does not use this PAM file):
  Ctrl+Alt+F3 (laptops: Ctrl+Alt+Fn+F3) → log in with your password →
  sudo phonekey disable && loginctl unlock-session <id from 'loginctl'> →
  exit → Ctrl+Alt+F7 (Fn+F7)
Backups of the original file are in {backups}/.   (see protocol/SECURITY.md §9)""",
}

AFTER_ENABLE = {
    "sudo": ("Before confirming, open a root shell in ANOTHER terminal (sudo -i) and keep it open\n"
             "until you have tested sudo in a third terminal.",
             "Test in a NEW terminal:  sudo -k && sudo true"),
    "unlock": ("Before confirming, keep this terminal open: 'sudo phonekey disable' here undoes it.",
               "Test: Super+L, wake the screen, approve on the phone. Then test Deny and a phone\n"
               "with Bluetooth off (the password box should appear)."),
}


def _require_root(what: str) -> bool:
    if os.geteuid() != 0:
        print(f"phonekey: {what} needs root: sudo phonekey {what}", file=sys.stderr)
        return False
    return True


def cmd_enable(args: argparse.Namespace) -> int:
    service = pamconfig.SERVICES[args.service]
    path = pamconfig.PAM_DIR / service.name
    if not args.dry_run and not _require_root("enable"):
        return 1
    module = pamconfig.installed_module()
    if module is None:
        print(f"phonekey: {pamconfig.MODULE_NAME} is not installed (run scripts/install.sh first)", file=sys.stderr)
        return 1
    status = daemon_status()
    if status is None or status.get("mode") != "system":
        print("phonekey: the PhoneKey system service is not running (systemctl status phonekeyd)", file=sys.stderr)
        return 1
    account = target_user(args)
    if not any(d["account"] == account for d in status["paired"]):
        print(f"phonekey: no phone is paired for '{account}' (sudo phonekey pair)", file=sys.stderr)
        return 1
    try:
        old = pamconfig.read_service_file(path)
        new = pamconfig.add(old, service)
    except (OSError, pamconfig.PamConfigError) as e:
        print(f"phonekey: {e}", file=sys.stderr)
        return 1

    timeout = service.timeout or 35
    before, test = AFTER_ENABLE[args.service]
    print(f"This adds PhoneKey to {path} (module: {module}):\n")
    print(pamconfig.diff(path, old, new))
    print(EFFECT[args.service].format(timeout=timeout) + "\n")
    print(RECOVERY[args.service].format(timeout=timeout, backups=pamconfig.BACKUP_DIR))
    print()
    if args.dry_run:
        print("Dry run: nothing was changed.")
        return 0
    print(before)
    if input("Type 'enable' to make this change: ").strip() != "enable":
        print("Nothing changed.")
        return 1
    saved = pamconfig.backup(path, old)
    pamconfig.write_atomic(path, new)
    print(f"\n✓ Enabled for {service.name}. Backup: {saved}")
    print(test)
    return 0


def cmd_disable(args: argparse.Namespace) -> int:
    """Removes every PhoneKey line from /etc/pam.d. Needs neither the phone nor the daemon."""
    files = pamconfig.enabled_files()
    if not files:
        print("PhoneKey is not enabled in any PAM file.")
        return 0
    if not args.dry_run and not _require_root("disable"):
        return 1
    for path in files:
        old = path.read_text()
        new = pamconfig.remove(old)
        print(pamconfig.diff(path, old, new))
        if args.dry_run:
            continue
        saved = pamconfig.backup(path, old)
        pamconfig.write_atomic(path, new)
        print(f"✓ Disabled for {path.name}. Backup of the previous version: {saved}")
    if args.dry_run:
        print("Dry run: nothing was changed.")
    return 0


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

    pair = sub.add_parser("pair", help="pair a phone over Bluetooth (needs phonekeyd)")
    pair.add_argument("--user", help="account to pair (default: the user who ran sudo)")
    pair.set_defaults(func=cmd_pair)

    enable = sub.add_parser("enable", help="use PhoneKey for a PAM service (shows the change, asks first)")
    enable.add_argument("service", choices=sorted(pamconfig.SERVICES))
    enable.add_argument("--dry-run", action="store_true", help="show the change without making it")
    enable.add_argument("--user", help="account that must have a paired phone (default: the user who ran sudo)")
    enable.set_defaults(func=cmd_enable)

    disable = sub.add_parser("disable", help="remove PhoneKey from all PAM files (works without the phone)")
    disable.add_argument("--dry-run", action="store_true", help="show the change without making it")
    disable.set_defaults(func=cmd_disable)

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
