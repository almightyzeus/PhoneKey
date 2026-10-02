# PhoneKey — Linux verifier

**Current state: Phase 6.** BLE pairing, end-to-end authentication
(`phonekey pair`, `phonekey test`), and opt-in `sudo` and lock-screen unlock
through the PAM module `pam_phonekey.so`. Login is not done.

Dependencies: Python 3 plus the Debian packages `python3-cryptography`,
`python3-dbus` and `python3-gi` (all preinstalled on Linux Mint). The daemon runs
**unprivileged**.

## Layout

```
linux/daemon/phonekey/      Python package
  codec.py                  strict TLV encoding (PROTOCOL.md §3–4)
  crypto.py                 ECDSA P-256 / SHA-256, labels, key loading
  registry.py               paired-device records (one JSON file per device)
  verifier.py               challenges, single-use pending table, pairing
  attestation.py            informational attestation summary
  framing.py                BLE message framing (≤ 244-byte frames)
  att.py                    minimal ATT client for the PhoneKey service
  ble.py                    LE scanning + bonding via BlueZ; own L2CAP LE socket
  core.py                   daemon logic: peers, pairing, auth, keepalive
  daemon.py                 phonekeyd: GLib main loop + Unix-socket API
  cli.py                    `phonekey` command
  simulator.py              software authenticator: tests + `--simulate` only
  paths.py                  development vs system locations
  pamconfig.py              the one-line edit behind `phonekey enable/disable`
  command.py                the sudo command line shown on the phone
  presence.py               sudo prompts only for someone at this computer (logind)
linux/cli/phonekey          development launcher for the CLI
linux/cli/phonekeyd         development launcher for the daemon
linux/systemd/              system service unit (installed by scripts/install.sh)
linux/pam/                  pam_phonekey.c (PAM module), pam_harness.c (tests only), Makefile
```

## Running during development (no installation)

```bash
linux/cli/phonekeyd -v          # terminal 1: the daemon, as your user
linux/cli/phonekey pair         # terminal 2: then "Add computer" on the phone
linux/cli/phonekey test         # authenticate on the phone
linux/cli/phonekey status
linux/cli/phonekey devices
linux/cli/phonekey unpair <prefix> | --all
linux/cli/phonekey test --simulate   # protocol self-test with a software phone
```

Development state lives in `~/.local/state/phonekey-dev/`, and the socket in
`$XDG_RUNTIME_DIR/phonekey/`. Only your own user can use them.

### Pairing

`phonekey pair` opens a 2-minute window. The phone must also be in pairing mode
(**Add computer**). The first time, Bluetooth bonding shows a 6-digit code in
the terminal and on the phone. Confirm only if they match. Then the phone
shows the computer's name, account and key fingerprint, and asks for your
fingerprint.

### How the laptop talks to the phone

- **The laptop is the BLE central.** Its Realtek RTL8822CU controller cannot
  advertise, so the phone advertises and the laptop connects.
- **The laptop opens its own LE-only connection.** The daemon opens an L2CAP LE
  socket to the phone's ATT channel and speaks a minimal subset of ATT
  (`att.py`). BlueZ's generic connect kept choosing classic Bluetooth for the
  dual-mode phone, and could have tried audio or phonebook profiles.
- **An encrypted, authenticated bond is required.** The socket demands one
  (`BT_SECURITY_HIGH`).
- **Keepalive:** a `STATUS` exchange every 20 s. A phone that stops answering is
  disconnected and reconnected.
- **BlueZ's role is limited** to LE scanning and the one-time bonding. The
  pairing agent exists only during the pairing window, is never the default
  agent, and accepts only numeric comparison.
- **Scanning only while needed** (`scanning.py`): none while every paired phone
  is connected; short bursts while one is missing (about 12 s every 30 s, then
  every 2 minutes after 5 minutes); an immediate burst when sudo or unlock
  needs the phone; continuous only while `phonekey pair` is open. Constant
  scanning made this laptop's Realtek adapter hang and broke a Bluetooth
  mouse's reconnection.

## Installing as a system service

```bash
make -C linux/pam                     # as your user; needs PAM headers (see linux/pam/Makefile)
sudo scripts/install.sh --dry-run     # lists every change, changes nothing
sudo scripts/install.sh               # asks you to type "install"
sudo scripts/uninstall.sh [--purge]   # removes it again (works without the phone)
```

It starts at every boot. If Bluetooth is off or not ready yet, it waits and
starts scanning when Bluetooth appears (SECURITY.md D‑14). On the phone,
PhoneKey starts by itself after a reboot (once you have unlocked the phone) and
after app updates, as long as a computer is paired.

The service runs as a dedicated `phonekey` user under a hardened systemd unit
(`linux/systemd/phonekeyd.service`). Its state is in `/var/lib/phonekey` and its
socket in `/run/phonekey/`. The install copies `pam_phonekey.so` into the PAM
module directory but **references it nowhere: no PAM, sudo, lock-screen,
login, Bluetooth or D-Bus configuration changes.** Stop the development daemon,
then pair again (`sudo phonekey pair`; the phone gets a new entry for the
system service). `phonekey logs` shows the service journal.

## Using PhoneKey for sudo (opt-in)

```bash
sudo phonekey enable sudo --dry-run   # shows the exact diff and recovery steps
sudo phonekey enable sudo             # same, then asks you to type "enable"
sudo phonekey disable                 # removes it again (no phone or daemon needed)
pkexec phonekey disable               # the same, if sudo itself misbehaves
```

`enable` adds two lines (a comment and
`auth sufficient pam_phonekey.so action=sudo`) to `/etc/pam.d/sudo`, right
before `@include common-auth`. Nothing else changes, and a copy of the file goes
to `/var/backups/phonekey/`. Then:

- **Phone connected:** sudo prints *PhoneKey: approve on your phone, or tap Deny to use your password*, and a
  fingerprint approves.
- **You tap Deny, or the phone does not answer within 35 s:** you get the
  usual password prompt.
- **Phone not connected, or daemon stopped:** you get the password prompt at
  once.

The phone shows the exact command, for example `sudo apt upgrade`. The daemon
reads it from the waiting sudo process itself, and the text is signed (`command.py`,
SECURITY.md D‑13). Only sudo run by someone at this computer reaches the phone:
over SSH, from cron or from a background service you get the password prompt
(`presence.py`, SECURITY.md D‑15). Approving is equivalent to typing your password for that
command. Deny prompts you did not start (SECURITY.md R‑8). The recovery procedures are in SECURITY.md §9.

## Using PhoneKey for the lock screen (opt-in)

```bash
sudo phonekey enable unlock --dry-run   # the exact diff and the recovery steps
sudo phonekey enable unlock             # same, then asks you to type "enable"
```

This adds `auth sufficient pam_phonekey.so action=unlock timeout=20` before
`@include common-auth` in `/etc/pam.d/cinnamon-screensaver`. When you wake the
locked screen it shows *PhoneKey: approve on your phone, or tap Deny to use your password*, and a fingerprint
unlocks. The password box appears when you tap Deny, after 20 s, or straight
away if the phone is not connected. If the lock screen gives up waiting, the
phone prompt is withdrawn. Recovery without the lock screen (text console,
Ctrl+Alt+Fn+F3) is in SECURITY.md §9.

### The PAM module

`pam_phonekey.c` is a thin client of about 300 lines with no cryptography.
It checks with SO_PEERCRED that `/run/phonekey/phonekey.sock` belongs to the
`phonekey` user, sends one JSON line, and maps the result (SECURITY.md D‑12).
`pam_harness` runs a PAM stack from a private directory with
`pam_start_confdir`, so the module can be tested against the development
daemon and a real phone without touching `/etc/pam.d`:

```bash
mkdir -p /tmp/pk && cp linux/pam/pam_phonekey.so /tmp/pk/
printf 'auth sufficient /tmp/pk/pam_phonekey.so action=test socket=%s daemon_user=%s\nauth requisite pam_deny.so\n' \
  "$XDG_RUNTIME_DIR/phonekey/phonekey.sock" "$USER" > /tmp/pk/phonekey-live
linux/pam/pam_harness /tmp/pk phonekey-live "$USER"
```

## Tests

```bash
scripts/linux-tests.sh          # ~180 tests, ~5 s, stdlib unittest
PHONEKEY_PAM_INCLUDE=/path/to/usr/include scripts/linux-tests.sh   # if libpam0g-dev is not installed
PHONEKEY_PAM_SANITIZE=1 scripts/linux-tests.sh                     # PAM module under ASan/UBSan
```

| Area | File |
|---|---|
| Codec rules and shared vectors (`protocol/test-vectors/v1.json`) | `tests/linux/test_codec.py` |
| Fuzzing: malformed input never crashes or authenticates | `tests/protocol/test_codec_fuzz.py` |
| Authentication: replay, tampering, unknown phone, revocation, expiry, busy, labels, versions | `tests/linux/test_verifier.py` |
| Pairing: proof of possession, nonce/hash binding, window, software keys | `tests/linux/test_pairing.py` |
| Attestation summary (informational) | `tests/linux/test_attestation.py` |
| Daemon logic over a fake link: pairing, auth, timeouts, disconnects, keepalive | `tests/linux/test_core.py` |
| BLE framing | `tests/linux/test_framing.py` |
| ATT client against a scripted Android-style GATT server | `tests/linux/test_att.py` |
| Local IPC authorization | `tests/linux/test_ipc.py` |
| PAM module through real libpam, against a fake daemon (skipped without PAM headers) | `tests/linux/test_pam.py` |
| PAM file edit: placement, exact removal, refusals, backups | `tests/linux/test_pamconfig.py` |
| Command shown for sudo: quoting, escaping, visible truncation | `tests/linux/test_command.py` |
| Local presence for sudo: SSH, cron/services, other users | `tests/linux/test_presence.py` |
| Registry: persistence, permissions, tamper detection | `tests/linux/test_registry.py` |
| CLI | `tests/linux/test_cli.py` |

The security checks were mutation-tested in Phase 2 (all 15 disabled checks
were caught). `ble.py` and `daemon.py` need real hardware and are covered by
the live tests: pairing, authentication with the phone unlocked and locked,
and recovery after an app restart.
