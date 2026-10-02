# PhoneKey — Security Model and Threat Analysis (draft)

> **PhoneKey is pre-alpha research software. It is not production-secure.**
> Keep normal password authentication enabled at all times. The design below
> has not been independently reviewed.

This document covers the protocol ([PROTOCOL.md](PROTOCOL.md)) and the MVP
implementation: an Android authenticator and a Linux Mint verifier.

## 1. Security goals

| ID | Goal |
|---|---|
| G‑1 | An action is authorized only if the **registered device key** signs a **fresh** verifier challenge describing that action. |
| G‑2 | The device private key **never leaves** Android Keystore. It is hardware-backed (StrongBox if available, otherwise TEE) and never software-only. |
| G‑3 | Every signature needs a **fresh Class 3 (strong) biometric** check on the phone. |
| G‑4 | **No biometric data** is stored or transmitted by PhoneKey. The app only learns "BiometricPrompt succeeded" from the OS. |
| G‑5 | Captured traffic cannot be **replayed**. |
| G‑6 | The phone prompts only for requests from **paired verifiers**, and it shows the action and target it will sign. |
| G‑7 | Every failure is **fail-closed** for PhoneKey and **fail-open to password** for the user. PhoneKey is always `sufficient`, never `required`. |
| G‑8 | PhoneKey can be **disabled and unpaired without the phone**. |
| G‑9 | **No network or cloud** dependency. |

## 2. Non-goals / explicit limits

- PhoneKey **cannot protect a compromised host**. An attacker with root on the
  laptop can edit PAM, the registry, or the daemon, and skip PhoneKey entirely
  (T‑7).
- PhoneKey does **not** prove physical distance. BLE range is an operational
  property, not a security boundary, and relaying is possible (R‑1).
- RSSI is **not** used for any security decision.
- PhoneKey does **not** replace disk encryption, and it does not unlock
  password-derived secrets (gnome-keyring, ecryptfs) (R‑4).

## 3. Assets

| Asset | Location | Protection |
|---|---|---|
| Device private key | Android Keystore (StrongBox/TEE) | Non-exportable; per-use biometric auth; invalidated on biometric enrollment change |
| Verifier private key | `/var/lib/phonekey/verifier_key.pem` | Owner `phonekey`, mode 0600. Only proves requests come from this verifier. |
| Paired-device registry (public keys) | `/var/lib/phonekey/devices/` | Owner `phonekey`, directory 0700. **Integrity-critical**: whoever can write here can register their own key. |
| Pending challenges | `phonekeyd` memory | Never written to disk. Single-use. 30 s lifetime. |
| PAM configuration | `/etc/pam.d/*` | Root only. Changed only by `phonekey enable` after explicit confirmation, with backups. |
| Biometric templates | Android OS / secure hardware | Never accessed by PhoneKey. |

## 4. Trust boundaries

```
 ┌────────── Android phone ──────────┐        ┌──────────────── Linux laptop ────────────────┐
 │ Secure HW (TEE/StrongBox)         │        │ root: PAM stack, sudo, lightdm, systemd      │
 │  • device key, biometric matcher  │        │                                              │
 │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │  BLE   │ user `phonekey`: phonekeyd (verifies sigs,   │
 │ PhoneKey app (untrusted by HW:    │◄──────►│   holds verifier key, registry, challenges)  │
 │  can only *request* signatures)   │ (LESC) │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
 └───────────────────────────────────┘        │ unix socket (SO_PEERCRED checked both ways)  │
                                              │ pam_phonekey.so in sudo (root) or            │
      Air: untrusted. Assume an attacker      │   cinnamon-screensaver (runs as the user)    │
      can sniff, inject, relay, spoof.        └──────────────────────────────────────────────┘
```

- **The air is hostile.** Security never depends on who is talking over BLE,
  only on signatures (G‑1) and on the verifier's single-use challenge table
  (G‑5). LESC encryption adds confidentiality and pairing authenticity.
- **The PhoneKey app is below the hardware.** Even a compromised app cannot
  get a signature without a biometric success, because Keystore enforces this.
  A compromised app *can* show misleading text in its own UI before invoking
  the prompt (see T‑9).
- **The PAM module trusts `phonekeyd`.** The module holds no keys and does no
  cryptography. It is a thin client that checks the socket peer is the
  `phonekey` user. `phonekeyd` checks that callers asking about account *X* are
  root or *X* themselves.

## 5. Threat model

Each threat names the mechanism that defeats it and the tests that show it
(Linux tests in `tests/`, Android tests in `android/app/src/{test,androidTest}`).

| ID | Threat | Expected result | Mechanism | Test (phase) |
|---|---|---|---|---|
| T‑1 | **Replay.** Attacker records a valid `AUTH_RESPONSE` and replays it later, or to another request. | FAIL | Response is bound to `request_id` and to `request_hash` (which covers the 256-bit challenge). The pending entry is deleted on first use. Nothing survives a daemon restart. | `test_verifier`: `replayed_assertion_rejected`, `assertion_for_other_request_rejected`, `assertion_with_swapped_request_id_rejected`, `pending_requests_do_not_survive_restart`; `test_core`: `replayed_response_over_link_ignored` |
| T‑2 | **MITM / tampering.** Attacker modifies BLE traffic, such as the action, challenge, or signature. | FAIL | Both directions are signed over the exact bytes. The link is LESC-encrypted. Any modification breaks the signature or `request_hash`. | `test_verifier`: `modified_challenge_rejected`, `modified_action_signed_by_phone_rejected`, `modified_or_stripped_detail_refused_by_phone`, `phone_signing_other_detail_rejected`; Android `AuthenticatorCoreTest.commandDetailIsShownOnlyWhenSigned`; `modified_signature_rejected`, `modified_request_hash_rejected`; Android `SignatureVerifierTest` (every byte), `AuthenticatorCoreTest.tamperedRequestIsRefused` |
| T‑3 | **Stolen phone.** Attacker holds the phone. | FAIL unless the attacker passes a Class 3 biometric | Per-use `AUTH_BIOMETRIC_STRONG` key. Neither the device credential (PIN) nor an unlocked screen can authorize a signature (D‑4). | On device: `KeystorePolicyTest.signingWithoutBiometricIsRefused`, `keyRequiresFreshStrongBiometricForEverySignature` |
| T‑4 | **Unknown phone.** A different Android device (or a different key on the same phone) answers. | FAIL | Only keys in the registry for that `account` are accepted. `device_id = H(pubkey)`, not a name or MAC. | `test_verifier`: `unregistered_key_rejected`, `request_for_unpaired_device_refused`, `response_from_other_devices_key_for_this_device_rejected`, `response_naming_another_device_rejected` |
| T‑5 | **Phone already unlocked, no biometric for this request.** | FAIL | Auth timeout 0: Keystore demands a `CryptoObject`-bound biometric for **each** signature. An unlocked screen gives no authorization. | On device: `KeystorePolicyTest.signingWithoutBiometricIsRefused`; live tests A (unlocked) and B (locked) |
| T‑6 | **BLE spoofing.** Attacker advertises the phone's service UUID, or connects to the phone pretending to be the laptop. | FAIL | Names and addresses are metadata only. The laptop connects only to bonded phones (or pairing-UUID phones during its own pairing window), and a fake phone cannot produce a device-key signature. A fake laptop cannot bond without the user confirming a code, and cannot sign `AUTH_REQUEST`, so the phone doesn't prompt (`UNKNOWN_VERIFIER`/`BAD_SIGNATURE`). | `test_verifier.phone_ignores_requests_from_unknown_verifier`; Android `AuthenticatorCoreTest.unknownVerifierIsRefusedWithoutPrompt`, `forgedVerifierSignatureIsRefused`. Laptop connects only to bonded or pairing-window phones: manual |
| T‑7 | **Laptop compromise.** Attacker is root on the laptop. | **Not defended.** | Out of scope. Root can rewrite PAM or the registry. An *unprivileged* local attacker is handled: it cannot write the registry, cannot impersonate `phonekeyd` (socket owned by `phonekey`, peer checked), and cannot request auth for other accounts (SO_PEERCRED). | `test_ipc`: `auth_only_for_own_account`, `pairing_requires_root_in_system_mode`, `pairing_in_dev_mode_only_for_own_account`, `pairable_accounts`, `sudo_action_only_from_root`, `actions_are_a_fixed_set`; `test_pam`: `socket_owned_by_another_user_is_not_used`, `unsafe_user_name_is_not_sent` |
| T‑8 | **Lost phone.** | Revocable | `sudo phonekey unpair <device>` deletes the registry entry and works without the phone or the daemon. `sudo phonekey disable` removes PAM integration. The password still works. | `test_verifier.unpaired_device_rejected`, `test_cli.unpair_by_prefix_and_all`, `test_pamconfig.remove_restores_original_exactly`; recovery drill (§9) when enabling sudo |
| T‑9 | **Prompt fatigue / phishing.** Attacker triggers requests hoping the user approves by reflex. | Mitigated | Only signed requests from paired verifiers prompt. At most one prompt at a time. Rate limit of 5/min per verifier. The prompt shows the verifier, action, target, and account. | `test_verifier.busy_when_request_pending`, `test_core.duplicate_request_while_pending_is_busy`. Android `PromptGateTest` (one prompt at a time, 5 per verifier per minute on a monotonic clock, refusals don't count); `test_presence` (sudo prompts only for someone at the computer, D‑15) |
| T‑10 | **Malformed input** over BLE or IPC (overflow, huge messages, bad TLV). | Rejected, no crash | Strict codec (§3 of PROTOCOL.md) with fixed limits. The daemon is Python (memory-safe). The C PAM module only looks for `"result"`/`"event"` string values in lines from the daemon (bounded buffers, 4 KiB cap), and only after checking the socket belongs to `phonekey`. Framing caps. | `test_pam` (also run under AddressSanitizer/UBSan: `oversized_reply`, `split_and_garbage_lines`, `ok_inside_another_string_is_not_success`), `tests/protocol/test_codec_fuzz`, `test_codec` + shared vectors (Python and Kotlin), `test_framing`, `test_att`, `test_core.malformed_frames_get_error_and_do_not_break_link` |
| T‑11 | **Pairing MITM.** Attacker inserts itself during `phonekey pair`. | FAIL, if the user compares the codes | LESC Numeric Comparison. The phone's characteristics require an authenticated link. App-level pairing needs **both** windows open: `phonekey pair` on the laptop and **Add computer** on the phone. The user also confirms the laptop's name, account and key fingerprint on the phone before the new key is created. | `test_pairing` (window, proof of possession, nonce/hash binding, one-shot); agent accepts only numeric comparison (`ble.PairingAgent`): manual; live pairing |
| T‑12 | **Denial of service** (jamming, disconnects, BUSY spam, local socket flooding). | Password fallback | PhoneKey is `sufficient`. Unavailable, timeout, and error all fall back to the password. Timeouts are bounded. The daemon accepts at most 64 local connections (8 per user), validates request types, and answers every request even if handling it fails. | `test_core`: `timeout_fails_closed`, `disconnect_mid_auth_fails_closed`, `phone_not_connected`, keepalive tests; `test_ipc.malformed_requests_are_rejected_not_crashing`; `test_pam`: `no_daemon_is_fast`, `unavailable_is_fast`, `silent_daemon_times_out`, `denied_then_password_module_succeeds`, `missing_module_does_not_block_the_stack`, `other_results_are_not_success` |
| T‑13 | **Downgrade / cross-protocol.** | FAIL | A single accepted `version`. Signature labels are domain-separated and include the version. | `test_verifier`: `wrong_label_rejected`, `unknown_version_rejected`; codec vector `unsupported version` |
| T‑14 | **Secrets in logs.** | None logged | Log only `request_id`, a short device-id prefix, the action, and the result. Never log keys, full messages, or attestation blobs. | Manual log review: logs show device-id prefixes, actions and results only |

## 6. Residual risks (accepted for the MVP, documented)

- **R‑1 Relay attack.** An attacker with one radio near the laptop and another
  near the phone can forward traffic, so the phone can be far away. The
  signature still verifies, because the attacker is just a pipe. What limits
  this: the user must actively pass a biometric on a prompt that names the
  laptop and action, and cannot be asked more than once at a time. Real
  distance bounding needs hardware support (e.g. UWB) and is out of scope. **If
  you get a PhoneKey prompt you did not trigger, deny it.**
- **R‑2 Host compromise** (T‑7).
- **R‑3 Careless pairing confirmation.** If the user confirms mismatched
  numeric codes, an attacker can pair. Mitigation: pairing requires root and
  opens only a short window.
- **R‑4 Password-derived secrets.** Logging in with PhoneKey cannot unlock
  gnome-keyring (and would not unlock an ecryptfs home). Phase 19 (login,
  deliberately late, D‑17) must decide and document the impact. The login path
  may stay password-only.
- **R‑5 App-level UI deception.** A malicious app update could show false text
  before the BiometricPrompt. The signed `AUTH_REQUEST` limits what it could
  sign to real requests from the paired verifier. Supply-chain security of
  builds is out of scope for the MVP.
- **R‑6 Biometric spoofing.** PhoneKey inherits the phone's Class 3 biometric
  false-accept rate and spoof resistance.
- **R‑7 Advertisement fingerprinting.** While not connected to its laptop, the
  phone advertises the fixed PhoneKey service UUID. Its Bluetooth address
  rotates, but the UUID lets a nearby observer notice that *a* PhoneKey user is
  present. It reveals no identity or keys. Mitigation: the phone advertises only
  while a paired laptop is disconnected.
- **R‑8 Any process running as you can ask for a sudo approval.** A script,
  a background job, or someone logged in to your account over SSH can run
  `sudo`, which makes your phone prompt. Approving it is the same as typing your
  password for that `sudo`, and sudo's usual 15-minute ticket follows.
  **Mitigated by D‑13:** the phone shows the exact command (for example
  `sudo apt upgrade`), signed by the laptop, so you approve a command, not an
  anonymous "sudo". What remains: a command that *looks* harmless can still do
  harm (e.g. installing a package the attacker prepared), `sudo -i`/`sudo -s`
  show only as a shell, and a truncated command is marked but not fully shown.
  **Also mitigated by D‑15:** sudo approvals reach the phone only for someone
  logged in at this computer; SSH sessions, cron jobs and background
  services get the password prompt. Code already running as you can get
  around D‑15 (e.g. `systemd-run --user --pty sudo …`), so it stops casual
  and automated triggers, not a determined attacker in your account.
  **Deny any prompt you did not start.**

- **R‑9 Unexpected "Unlock screen" prompts.** Any program running as you can
  ask for an unlock approval (D‑16). Approving it unlocks nothing, but a
  prompt you did not cause is a sign something is wrong: **deny it**. The
  real unlock prompt appears only the moment you wake your locked screen.

## 7. Security-sensitive decisions (need explicit sign-off)

| ID | Decision | Choice | Trade-off |
|---|---|---|---|
| D‑1 | Pairing authenticity | BLE LESC Numeric Comparison: the phone's system dialog and the code printed by `phonekey pair`, answered through PhoneKey's own BlueZ agent (registered only during the pairing window, never the default agent, numeric comparison only). App keys are exchanged inside the authenticated link. | Uses the standard Bluetooth mechanism with no extra dependencies. It relies on the BT stacks' LESC implementations and on the user comparing codes. Alternative: QR code with a one-time secret. |
| D‑2 | Where signatures are verified | In `phonekeyd` (Python), not in the C PAM module | Keeps the C code in root processes tiny, with no crypto or parsing. The daemon is fully trusted, but it holds nothing more sensitive than PAM itself. |
| D‑3 | Key security level | StrongBox **detected at runtime** with TEE fallback. **Software keys are refused.** | The test device (Motorola Edge 50 Fusion) has **no StrongBox**, as confirmed in Phase 1, so its keys are TEE-backed. TEE is still hardware-isolated. |
| D‑4 | `setUnlockedDeviceRequired` | **Off** (decided 2026‑09‑27, after on-device testing) | With it on, the Edge 50 Fusion kept keys sealed (`Required super decryption key is not in memory → LOCKED`) whenever the phone had last been unlocked by a non-strong method such as face unlock. PhoneKey then failed with the phone unlocked, and locked-phone requests needed an unlock plus a second fingerprint. The per-signature Class 3 fingerprint (D‑6) remains the authorization. The cost: the key is not additionally sealed while the phone is locked. |
| D‑5 | Attestation | **Informational only.** Recorded and displayed, never required. | Not requiring it means the verifier cannot prove the key is hardware-backed. It relies on the app's own check (D‑3). |
| D‑6 | Biometric class | `BIOMETRIC_STRONG` only, no device-credential fallback in the prompt | Face unlock on many phones is Class 1/2 and won't work. After a lockout the user falls back to the laptop password. |
| D‑7 | Daemon privilege | Runs **unprivileged**. In development it runs as the user from the repo, with no installation and no D-Bus policy file. The system service runs as a dedicated `phonekey` user under a hardened unit (no capabilities, read-only system, only Unix and Bluetooth sockets); BlueZ's stock D-Bus policy already allows it. | Verified on the MVP laptop: LE scanning (BlueZ), bonding through a non-default agent (BlueZ), and the daemon's own L2CAP LE ATT socket all work without privileges. |
| D‑8 | PAM placement | `auth sufficient pam_phonekey.so action=sudo` added to **one service file** (`/etc/pam.d/sudo` first) before `@include common-auth`, only by `sudo phonekey enable sudo` after it shows the diff and you type `enable`. `common-auth` is never edited. The editor refuses files it does not recognise (not exactly one `@include common-auth`, earlier `auth` rules, not root-owned), backs up the file to `/var/backups/phonekey/`, and replaces it atomically. | Limits the blast radius. Each service is enabled explicitly. |
| D‑9 | Replay state in memory only | Yes | A restart invalidates in-flight requests, which is the safe direction. |
| D‑10 | Optional hardening: BlueZ `SecureConnections = only` in `/etc/bluetooth/main.conf` | **Not applied** in the MVP | It would prevent legacy pairing system-wide, which could affect your other BT devices. Changing it needs explicit approval. |
| D‑11 | BLE roles and link | Phone = peripheral (GATT server, advertises); laptop = central, connecting over **its own L2CAP LE socket** to the phone's ATT channel, with a minimal ATT client (`att.py`) | The laptop's Realtek RTL8822CU rejects all LE advertising. Android derives a classic-Bluetooth bond during LE pairing and its advertisements carry no "BR/EDR not supported" flag, so BlueZ's `Device1.Connect` kept choosing classic Bluetooth (failed reconnects, and it could try audio/phonebook profiles). The socket requires `BT_SECURITY_HIGH` (authenticated, encrypted bond). Roles carry no security meaning. See R‑7. |
| D‑12 | PAM results and waiting | Approved → success. Denied on the phone → `PAM_AUTH_ERR`. Anything else (no daemon, socket not owned by `phonekey`, no phone connected, timeout, error) → `PAM_AUTHINFO_UNAVAIL`. With `sufficient`, every non-success goes on to the password prompt. The module waits at most 35 s (the daemon's request lives 30 s). | While the phone prompt is open, the password prompt waits. Tap **Deny** on the phone to get it at once. When no phone is connected, the module returns in milliseconds. |
| D‑13 | What the phone shows for sudo | The daemon reads the command line of the process that connected (SO_PEERCRED pid) when that process is root and named `sudo`/`sudoedit`, shell-quotes it, escapes control/bidi characters, and caps it at 256 bytes with a visible truncation marker. It is sent as the signed `detail` field and shown on the request screen and inside the fingerprint prompt. The `sudo` action is accepted only from root callers. | Clients cannot supply the text, so it cannot be spoofed by an unprivileged program. The command can be visible on the lock screen while a prompt is open. |
| D‑14 | Starting automatically | **Laptop:** `phonekeyd` is a normal boot service (unprivileged user, hardened unit). If Bluetooth is off or not ready it keeps running and starts scanning when Bluetooth appears; if there is no adapter yet, systemd retries every 5 s. **Phone:** a non-exported receiver starts the service after boot (`BOOT_COMPLETED`, which Android sends only after the first unlock) and after an app update (`MY_PACKAGE_REPLACED`), only if a computer is paired and the Bluetooth permissions are granted. | Starting grants nothing: each approval still needs a fingerprint, and while nothing runs sudo simply asks for the password. The cost: after a reboot the phone advertises the PhoneKey service UUID whenever its laptop is not connected (R‑7), without the app being opened first. |
| D‑15 | Who may trigger a sudo prompt | Only someone at this computer (`presence.py`). If the `sudo` process is in a logind session, that session must be local, the account's own, and active. Desktop terminals run outside the login session (under `user@UID.service`), so otherwise the process must have a controlling terminal **and** the account must have an active local session on a seat. Any lookup failure refuses. Refused requests never reach the phone: the result is `unavailable`, and sudo asks for the password. | Blocks SSH logins, cron jobs and background services. Not a hard boundary against code already running as the user (R‑8). |
| D‑16 | Screen unlock | `auth sufficient pam_phonekey.so action=unlock timeout=20` before `@include common-auth` in `/etc/pam.d/cinnamon-screensaver`, only via `sudo phonekey enable unlock`. The lock screen runs PAM as soon as you wake it, so the phone is asked first; the password box appears when you deny, after 20 s, or at once if the phone is not connected. Presence: Cinnamon's PAM helper is a D-Bus-activated user service with no logind session and no terminal, and `LockedHint` is not maintained, so the rule is only that the account has an active local session on a seat. When the lock screen gives up, the daemon withdraws the phone prompt (PROTOCOL.md §8.1 step 8). | The requester cannot be proven to be the lock screen; a program running as you that fakes an unlock request only gets "ok" back and unlocks nothing (R‑9). After a phone unlock, `pam_gnome_keyring` (which follows in the stack) does not run; the keyring normally stays unlocked for the session anyway. |
| D‑17 | When Linux login is integrated | **Last major implementation phase** (Phase 19 in [docs/ROADMAP.md](../docs/ROADMAP.md)), after reliability, pairing, hardening, UX, packaging, compatibility and independent review (decided 2026-09-30). | Login runs during boot and session start, depends on the display manager and start-up ordering, and a mistake can lock the user out of the desktop; it also cannot unlock password-derived secrets (R‑4). Sudo and screen unlock cover the frequent cases with far less risk. |
| D‑18 | Reliability before new surfaces | Phase 7 (reliability and resilience) comes before any new authentication surface (decided 2026-09-30). | New surfaces multiply failure modes; the existing ones must first be dependable in daily use, with password fallback proven in every failure mode. |
| D‑19 | QR-assisted pairing | QR pairing **complements** authenticated BLE pairing: the first implementation (Option A) adds QR-based application binding and **keeps** LE Secure Connections numeric comparison (decided 2026-09-30). QR + BLE Just Works (Option B) is a **security-model change** that must not silently replace Option A and needs its own decision. | Option A strictly adds security (it addresses R‑3). Option B would leave the link unprotected against a man-in-the-middle who could read request contents, and it conflicts with the authenticated-bond requirement (PROTOCOL.md §5.1). Android apps cannot use Bluetooth OOB pairing, so a QR code cannot secure the bond itself. |
| D‑20 | Protocol scope | The protocol stays transport-agnostic and authorizes **an action on a resource** for an account (PROTOCOL.md intro), not "unlock Linux". Linux-specific parts (PAM, action names such as `linux.sudo`) stay in the verifier (decided 2026-09-30). | Keeps future verifiers possible (ROADMAP Phase 15) without building integrations early. |

## 8. Platform constraints

### 8.1 Android Keystore / BiometricPrompt

- Per-use auth (timeout 0) **requires** `BiometricPrompt.CryptoObject(signature)`.
  Calling `sign()` without it throws. The Phase 1 tests exercise this.
- `AUTH_BIOMETRIC_STRONG` accepts only Class 3 sensors. On the Motorola Edge 50
  Fusion, `canAuthenticate(BIOMETRIC_STRONG)` succeeds with fingerprint
  (verified in Phase 1).
- StrongBox supports only P‑256 EC (which we use), and it is slower (hundreds of
  ms per signature). `StrongBoxUnavailableException` → retry TEE-backed.
- `setInvalidatedByBiometricEnrollment(true)` → `KeyPermanentlyInvalidatedException`
  after enrollment changes, and the phone must be re-paired.
- Private keys are non-exportable: `PrivateKey.getEncoded()` returns `null`,
  and no API returns key material. The Phase 1 tests check this.
- **minSdk = 33** (Android 13). `KeyInfo.getSecurityLevel()` needs API 31, and
  API 33 adds the GATT-server notify API and the notification permission. The
  app needs `BLUETOOTH_CONNECT` and `BLUETOOTH_ADVERTISE`, but no scanning or
  location permission.
- Background BLE needs a foreground service (`connectedDevice` type on
  API 34+) and a visible notification. Some vendors kill background services
  aggressively, so a battery-optimization exemption may be requested.
- A BiometricPrompt needs an Activity in the foreground. An incoming request
  therefore raises a high-priority notification / full-screen intent that opens
  the request screen. It shows over the lock screen, and one fingerprint
  approves (verified on the test phone). On Android 14+ the user must allow
  full-screen notifications; the app offers a button for that.

### 8.2 Linux Mint / BlueZ / PAM

- BlueZ 5.72 over D-Bus. The daemon uses only the **central** role: LE
  discovery filtered to PhoneKey UUIDs, `Device1.Connect/Pair`, and the remote
  GATT characteristics. The adapter reports peripheral support, but its
  controller (Realtek RTL8822CU, firmware 0x0cc6d2e3) rejects every LE
  advertisement with *Invalid Parameters* (D‑11).
- Pairing confirmation is handled by PhoneKey's own agent during the pairing
  window (D‑1); the desktop's default agent (Blueman) is not involved.
- Continuous LE discovery made the MVP adapter (Realtek RTL8822CU) stop
  answering "disable scanning" after an hour or two (`Opcode 0x2042 failed:
  -110`), which also broke the kernel's background scan that other devices,
  such as a BLE mouse, need to reconnect. The daemon therefore scans only
  while a paired phone is missing, in short bursts (`scanning.py`), and
  continuously only during a pairing window.
- A USB Bluetooth adapter can reset and come back as a new `hciN`. The daemon
  notices within 5 s, drops its links and scans on the new adapter.
- `sudo` runs PAM as **root**. `cinnamon-screensaver` runs PAM **as the
  logged-in user**. The daemon socket must therefore be connectable by users,
  and must authorize requests by SO_PEERCRED uid.
- `cinnamon-screensaver` starts PAM as soon as the locked screen is woken (mouse
  or key), in a helper that is a D-Bus-activated user service with no logind
  session and no terminal. PhoneKey runs first and the password box appears
  after it (resolved in Phase 6, D‑16).
- `lightdm` (slick-greeter) login: PhoneKey cannot provide the password that
  gnome-keyring and ecryptfs need (R‑4).
- `/etc/pam.d/common-auth` is shared by nearly every service, so PhoneKey
  **never** edits it.

## 9. Recovery procedures

These work **without the phone** and **without `phonekeyd` running**.

1. **Normal fallback.** If PhoneKey is unavailable, times out, or is denied, the
   next module in the stack (`pam_unix`) asks for your password as usual.
2. **Disable PhoneKey:** `sudo phonekey disable`. It removes the PhoneKey
   lines from every file in `/etc/pam.d`, leaving the rest byte-for-byte as it
   was. Each version it replaces is kept in `/var/backups/phonekey/`.
   **If sudo itself misbehaves**, use `pkexec phonekey disable`: `pkexec` is
   authorized by polkit with your password through its own PAM service
   (`/usr/lib/pam.d/polkit-1`), not through `/etc/pam.d/sudo`.
3. **Revoke a phone:** `sudo phonekey unpair <device-id-prefix>` (or
   `--all`). This deletes the registry entry. Also remove the BLE bond:
   `bluetoothctl remove <address>`.
4. **Manual recovery** if the `phonekey` CLI is broken:
   `sudo sed -i '/pam_phonekey\.so/d' /etc/pam.d/sudo` (and any other enabled
   service file), then `sudo systemctl disable --now phonekeyd`.
5. **If both sudo and pkexec are broken:** Linux Mint locks the root password by
   default, so `su -` is usually not an option. Instead, boot **recovery mode**
   from the GRUB menu (Advanced options → recovery mode → root shell), run
   `mount -o remount,rw /`, then `phonekey disable` or step 4.
   **Before enabling PhoneKey for sudo, open a separate root shell and keep it
   open until you have verified sudo works both with and without the phone.**

**Screen unlock (Phase 6).** The text consoles use `/etc/pam.d/login`, which
PhoneKey never touches, so they always accept your password:

1. Press **Ctrl+Alt+F3** (on many laptops **Ctrl+Alt+Fn+F3**). A black text
   screen shows `<hostname> login:`.
2. Log in with your user name and password.
3. Run `sudo phonekey disable`, then `loginctl unlock-session <id>` (the id
   of your desktop session is in `loginctl`, e.g. `c2`). Nothing is printed.
4. `exit`, then **Ctrl+Alt+F7** (or Fn+F7). The desktop is back, unlocked.

Rehearsed on the MVP laptop before enabling unlock (2026-09-29). Phase 19
(login, see docs/ROADMAP.md) will add its own procedure before it is enabled.

## 10. Rules for contributors

- Never use or invent custom crypto primitives, and never commit keys, test
  credentials, or `*.jks` files.
- Never log secrets or full protocol messages.
- Never make PhoneKey `required`/`requisite`, and never edit `common-auth`.
- Never change PAM or system configuration without an explicit confirmation
  step that shows the exact diff and the recovery path.
- Every new threat or decision goes into this document before its code.
