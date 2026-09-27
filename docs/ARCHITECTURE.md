# PhoneKey — Architecture (MVP)

This is the Linux- and Android-specific design. The platform-independent
protocol is in [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md). The threat
model is in [../protocol/SECURITY.md](../protocol/SECURITY.md).

## 1. Components

```
Android phone (authenticator, BLE peripheral)       Linux Mint laptop (verifier, BLE central)
┌──────────────────────────────────────┐          ┌───────────────────────────────────────────┐
│ PhoneKeyService (foreground,         │          │ phonekeyd (Python 3, unprivileged)        │
│   connectedDevice)                   │          │  ├─ ble.py      LE scan + bonding (BlueZ) │
│  ├─ GATT server: A2V (indicate),     │◄── BLE ──│  │              own L2CAP LE socket, with │
│  │   V2A (write); MITM-bond only     │   LESC   │  │              att.py (minimal ATT)      │
│  ├─ advertises only while its laptop │  bonded  │  ├─ core.py     peers, pairing, auth      │
│  │   is disconnected (or pairing)    │          │  ├─ verifier.py challenges, verification │
│  └─ AuthenticatorCore (codec, rules) │          │  ├─ registry.py paired devices            │
│ AuthRequestActivity                  │          │  └─ daemon.py   Unix socket (SO_PEERCRED) │
│  └─ BiometricPrompt + CryptoObject   │          └──────────────▲─────────────────▲──────────┘
│ PairingActivity, MainActivity        │                         │                 │
│ DeviceKeyStore: AndroidKeyStore P-256│          ┌──────────────┴─────┐  ┌────────┴─────────┐
│   (StrongBox → TEE fallback)         │          │ pam_phonekey.so    │  │ phonekey (CLI)   │
└──────────────────────────────────────┘          │ (C, no crypto, P5) │  └──────────────────┘
                                                  └────────────────────┘
      Pairing codes are confirmed in Android's dialog and in the desktop's Blueman dialog.
```

### Why these choices

- **The phone is the peripheral and the laptop is the central.** The MVP laptop's
  Realtek RTL8822CU controller rejects every LE advertisement, but scanning and
  connecting work. Roles don't matter for security (SECURITY.md D‑11). They also
  make messages point-to-point: the laptop writes to one specific phone.
- **The laptop opens the LE link itself.** Your phone is dual-mode, and Android
  also derives a classic-Bluetooth bond during LE pairing, so BlueZ's generic
  `Device1.Connect` kept choosing classic Bluetooth (and could try audio or
  phonebook profiles). The daemon instead opens an L2CAP LE socket to the
  phone's ATT channel (requiring the authenticated, encrypted bond) and speaks a
  minimal subset of ATT itself. BlueZ is used only for scanning and the
  one-time bonding.
- **No advertising, no default agent, no D-Bus policy on the laptop.** A pairing
  agent exists only during `phonekey pair`, is never the default agent, and
  accepts only numeric comparison. Nothing is installed during development.
- **Python daemon.** It uses only packages already on Mint
  (`python3-cryptography`, `python3-dbus`, `python3-gi`), and it is
  memory-safe for parsing untrusted BLE input.
- **Thin C PAM module (Phase 5).** Keeps crypto and parsing out of the
  `sudo`/`cinnamon-screensaver` processes (SECURITY.md D‑2).

## 2. Processes, users, files

| Path | Owner / mode | Contents |
|---|---|---|
| `/usr/lib/phonekey/` | root 0755 | Daemon and CLI Python package |
| `/usr/bin/phonekey` | root 0755 | CLI entry point |
| `/lib/x86_64-linux-gnu/security/pam_phonekey.so` | root 0644 | PAM module (Phase 5) |
| `/etc/phonekey/phonekey.conf` | root 0644 | Timeouts, rate limits, log level |
| `/var/lib/phonekey/` | phonekey 0700 | `verifier_key.pem` (0600), `devices/<device_id>.json` |
| `/run/phonekey/phonekey.sock` | phonekey, socket 0666 in dir 0755 | IPC. Authorization is by SO_PEERCRED, not file mode. |
| `/var/backups/phonekey/` | root 0700 | Pristine copies of PAM files before `phonekey enable` (Phase 5) |
| `/etc/systemd/system/phonekeyd.service` | root 0644 | `User=phonekey`, `SupplementaryGroups=bluetooth`, hardening options (`ProtectSystem=strict`, `NoNewPrivileges`, …) |

The daemon never runs as root. Everything above is installed only by
`scripts/install.sh` (Phase 3+) after showing the exact list of changes.

### Local IPC (Linux-only, not part of the protocol)

- **PAM → daemon.** One line in, one line out:
  - in: `AUTH <account> <service> <tty>\n`
  - out: `OK`, `UNAVAILABLE`, `DENIED`, or `ERROR`

  The daemon rejects the request unless the caller's uid is 0 or the uid of
  `<account>`. The module rejects the connection unless the peer uid is
  `phonekey`.
- **CLI → daemon.** JSON lines: `status`, `devices`, `test`, `pair`, `unpair`.
  Admin operations require peer uid 0.
- `phonekey unpair` and `phonekey disable` also work when the daemon is
  stopped, by editing files directly as root.

### PAM result mapping (Phase 5)

| Daemon reply | PAM return | Effect with `auth sufficient` |
|---|---|---|
| `OK` | `PAM_SUCCESS` | Authenticated, stack stops |
| `UNAVAILABLE` (no phone, daemon down, timeout) | `PAM_AUTHINFO_UNAVAIL` | Continue → password prompt |
| `DENIED` / `ERROR` | `PAM_AUTH_ERR` | Continue → password prompt |

## 3. Sequence: `sudo` with PhoneKey (Phase 5 target)

```
user         sudo+pam_phonekey      phonekeyd                 phone app          Keystore
 │ sudo apt …   │                      │                          │                  │
 │─────────────►│ AUTH chinuzeus sudo  │                          │                  │
 │              │─────────────────────►│ phone connected? yes     │                  │
 │ "Approve on  │                      │ new request_id+challenge │                  │
 │  your phone" │                      │ sign AUTH_REQUEST ──────►│ verify verifier  │
 │              │                      │                          │ show request     │
 │              │                      │                          │ BiometricPrompt ─┤ fingerprint
 │              │                      │                          │◄── sign ─────────┤
 │              │                      │◄──── AUTH_RESPONSE ──────│                  │
 │              │                      │ verify + consume         │                  │
 │              │◄────────── OK ───────│                          │                  │
 │  command runs│                      │                          │                  │
```

When the phone is absent, the daemon answers `UNAVAILABLE` at once, and sudo
shows its usual `[sudo] password for …` prompt.

## 4. Repository layout

```
phonekey/
├── android/              Android Studio project (Kotlin)        — Phase 1
├── linux/
│   ├── daemon/phonekey/  Python package: codec, crypto, registry,
│   │                     verifier, simulator, cli (phonekeyd in P3) — Phase 2/3
│   ├── pam/              pam_phonekey.c + Makefile              — Phase 5
│   └── cli/phonekey      `phonekey` launcher                    — Phase 2
├── protocol/
│   ├── PROTOCOL.md       platform-independent protocol
│   ├── SECURITY.md       threat model, decisions, recovery
│   └── test-vectors/     shared codec/signature vectors          — Phase 1/2
├── tests/                cross-component and Linux tests
├── docs/                 architecture, environment, how-tos
└── scripts/              install/uninstall (explicit, confirming)
```

## 5. Phase plan

| Phase | Deliverable | Touches system config? |
|---|---|---|
| 0 | These documents | No |
| 1 | Android app: Keystore key, BiometricPrompt, local sign + verify, tests | No |
| 2 | Linux verifier library + CLI: challenges, registry, verify, replay rejection, codec, test vectors | No (user-local test paths) |
| 3 | BLE transport: GATT server, agent, pairing, Android GATT client | Installs daemon + systemd unit **after confirmation** |
| 4 | End-to-end `phonekey test` | No |
| 5 | `pam_phonekey.so` for `sudo` + `phonekey enable/disable` | Edits `/etc/pam.d/sudo` **after explicit confirmation** |
| 6 | Screen unlock (`cinnamon-screensaver`) | Edits its PAM file **after confirmation** |
| 7 | Login (`lightdm`), if practical | Edits its PAM file **after confirmation** |
