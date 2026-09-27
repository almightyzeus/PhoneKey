# PhoneKey — Architecture (MVP)

This is the Linux- and Android-specific design. The platform-independent
protocol is in [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md). The threat
model is in [../protocol/SECURITY.md](../protocol/SECURITY.md).

## 1. Components

```
Android phone (authenticator)                     Linux Mint laptop (verifier)
┌───────────────────────────────────┐            ┌──────────────────────────────────────────┐
│ PhoneKeyService (foreground,      │            │ phonekeyd  (Python 3, user `phonekey`)   │
│   connectedDevice)                │            │  ├─ ble/gatt_server  BlueZ GattManager1  │
│  ├─ GattClient  ──────────────────┼── BLE ────►│  ├─ ble/advertiser   LEAdvertisingMgr1   │
│  │   autoConnect to bonded laptop │   LESC     │  ├─ ble/agent        Agent1 (pairing)    │
│  ├─ ProtocolCodec (TLV, §3)       │  bonded    │  ├─ protocol/codec   TLV (§3)            │
│  └─ RequestValidator              │            │  ├─ crypto           ECDSA P-256 verify  │
│ AuthRequestActivity               │            │  ├─ registry         /var/lib/phonekey   │
│  └─ BiometricPrompt + CryptoObject│            │  ├─ challenges       in-memory, 1-use    │
│ KeyManager                        │            │  └─ ipc              /run/phonekey/*.sock│
│  └─ AndroidKeyStore P-256         │            └───────────▲──────────────────▲───────────┘
│     (StrongBox → TEE fallback)    │                        │ unix socket      │
│ PairingActivity, MainActivity,    │            ┌───────────┴───────┐  ┌───────┴──────────┐
│ SettingsActivity                  │            │ pam_phonekey.so   │  │ phonekey (CLI,   │
└───────────────────────────────────┘            │ (C, ~150 lines,   │  │  Python)         │
                                                 │  no crypto)       │  └──────────────────┘
                                                 └───────────────────┘
                                                   loaded by sudo / cinnamon-screensaver
```

### Why these choices

- **The laptop is the GATT peripheral and the phone is the central.** The
  laptop has a stable public address and can advertise cheaply. BlueZ's GATT
  server API is well documented with Python examples. Android maintains
  `autoConnect` connections to bonded devices well from a foreground service.
- **Python daemon.** It uses only packages already on Mint
  (`python3-cryptography`, `python3-dbus`, `python3-gi`), and it is
  memory-safe for parsing untrusted BLE input.
- **Thin C PAM module.** PAM modules must be shared objects loaded into
  `sudo`/`cinnamon-screensaver`. Keeping them free of crypto and parsing keeps
  that attack surface tiny (SECURITY.md D‑2).

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
│   ├── daemon/           phonekeyd (Python package `phonekey`)  — Phase 2/3
│   ├── pam/              pam_phonekey.c + Makefile              — Phase 5
│   └── cli/              `phonekey` command                     — Phase 2
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
