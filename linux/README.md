# PhoneKey — Linux verifier

**Current state: Phases 3–4 done.** BLE pairing and end-to-end authentication
with the Android app work: `phonekey pair` and `phonekey test`. PAM
integration (sudo, lock screen) is not written yet.

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
linux/cli/phonekey          development launcher for the CLI
linux/cli/phonekeyd         development launcher for the daemon
linux/systemd/              system service unit (installed by scripts/install.sh)
linux/pam/                  (Phase 5)
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
- **BlueZ's role is limited** to LE scanning (restarted if BlueZ stops it) and
  the one-time bonding. The pairing agent exists only during the pairing
  window, is never the default agent, and accepts only numeric comparison.

## Installing as a system service (Phase 5 prerequisite; not done yet)

```bash
sudo scripts/install.sh --dry-run     # lists every change, changes nothing
sudo scripts/install.sh               # asks you to type "install"
sudo scripts/uninstall.sh [--purge]   # removes it again (works without the phone)
```

The service runs as a dedicated `phonekey` user under a hardened systemd unit
(`linux/systemd/phonekeyd.service`). Its state is in `/var/lib/phonekey` and its
socket in `/run/phonekey/`. **The install touches no PAM, sudo, lock-screen,
login, Bluetooth or D-Bus configuration.** Pair again after installing
(`sudo phonekey pair`). `phonekey logs` shows the service journal.

## Tests

```bash
scripts/linux-tests.sh          # ~150 tests, ~3 s, stdlib unittest
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
| Registry: persistence, permissions, tamper detection | `tests/linux/test_registry.py` |
| CLI | `tests/linux/test_cli.py` |

The security checks were mutation-tested in Phase 2 (all 15 disabled checks
were caught). `ble.py` and `daemon.py` need real hardware and are covered by
the live tests: pairing, authentication with the phone unlocked and locked,
and recovery after an app restart.
