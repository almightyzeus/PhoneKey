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

Each threat names the mechanism that defeats it and the test that must show it.
The test names are the planned names; the tests are written in the phase shown.

| ID | Threat | Expected result | Mechanism | Test (phase) |
|---|---|---|---|---|
| T‑1 | **Replay.** Attacker records a valid `AUTH_RESPONSE` and replays it later, or to another request. | FAIL | Response is bound to `request_id` and to `request_hash` (which covers the 256-bit challenge). The pending entry is deleted on first use. Nothing survives a daemon restart. | `tests/linux/test_verifier.py::test_replayed_assertion_rejected`, `::test_assertion_for_other_request_rejected` (P2) |
| T‑2 | **MITM / tampering.** Attacker modifies BLE traffic, such as the action, challenge, or signature. | FAIL | Both directions are signed over the exact bytes. The link is LESC-encrypted. Any modification breaks the signature or `request_hash`. | `test_modified_challenge_rejected`, `test_modified_signature_rejected`, `test_modified_action_rejected` (P1/P2); on-air fuzz tests (P3) |
| T‑3 | **Stolen phone.** Attacker holds the phone. | FAIL unless the attacker passes a Class 3 biometric | Per-use `AUTH_BIOMETRIC_STRONG` key; `setUnlockedDeviceRequired`. Device credential (PIN) alone cannot unlock the key. | Instrumented `KeyPolicyTest.signWithoutBiometricFails` (P1) |
| T‑4 | **Unknown phone.** A different Android device (or a different key on the same phone) answers. | FAIL | Only keys in the registry for that `account` are accepted. `device_id = H(pubkey)`, not a name or MAC. | `test_unregistered_key_rejected` (P2), live test (P4) |
| T‑5 | **Phone already unlocked, no biometric for this request.** | FAIL | Auth timeout 0: Keystore demands a `CryptoObject`-bound biometric for **each** signature. An unlocked screen gives no authorization. | `KeyPolicyTest.signWithoutBiometricFails` (P1) |
| T‑6 | **BLE spoofing.** Attacker advertises the laptop's or phone's name, or clones a MAC address. | FAIL | Names and addresses are metadata only. A fake verifier cannot sign `AUTH_REQUEST`, so the phone doesn't prompt (`UNKNOWN_VERIFIER`/`BAD_SIGNATURE`). A fake phone cannot produce a device-key signature. | `test_request_from_unknown_verifier_not_prompted` (P3), live test (P4) |
| T‑7 | **Laptop compromise.** Attacker is root on the laptop. | **Not defended.** | Out of scope. Root can rewrite PAM or the registry. An *unprivileged* local attacker is handled: it cannot write the registry, cannot impersonate `phonekeyd` (socket owned by `phonekey`, peer checked), and cannot request auth for other accounts (SO_PEERCRED). | `test_ipc_rejects_foreign_account` (P5) |
| T‑8 | **Lost phone.** | Revocable | `sudo phonekey unpair <device>` deletes the registry entry and works without the phone or the daemon. `sudo phonekey disable` removes PAM integration. The password still works. | `test_unpaired_device_rejected` (P2), manual recovery drill (P5) |
| T‑9 | **Prompt fatigue / phishing.** Attacker triggers requests hoping the user approves by reflex. | Mitigated | Only signed requests from paired verifiers prompt. At most one prompt at a time. Rate limit of 5/min per verifier. The prompt shows the verifier, action, target, and account. | `test_busy_when_prompt_open`, `test_rate_limit` (P3) |
| T‑10 | **Malformed input** over BLE or IPC (overflow, huge messages, bad TLV). | Rejected, no crash | Strict codec (§3 of PROTOCOL.md) with fixed limits. The daemon is Python (memory-safe). The C PAM shim parses a single fixed short token. Framing caps. | Codec vectors and fuzz tests `tests/protocol/test_codec_fuzz.py` (P2) |
| T‑11 | **Pairing MITM.** Attacker inserts itself during `phonekey pair`. | FAIL, if the user compares the codes | LESC Numeric Comparison. Characteristics require an authenticated link. Pairing is possible only during an explicit root-initiated window. | Manual pairing test with mismatched code (P3) |
| T‑12 | **Denial of service** (jamming, disconnects, BUSY spam). | Password fallback | PhoneKey is `sufficient`. Unavailable, timeout, and error all fall back to the password. Timeouts are bounded. | `test_disconnect_mid_auth_fails_closed`, PAM tests with daemon stopped or phone absent (P3/P5) |
| T‑13 | **Downgrade / cross-protocol.** | FAIL | A single accepted `version`. Signature labels are domain-separated and include the version. | `test_wrong_label_rejected`, `test_unknown_version_rejected` (P2) |
| T‑14 | **Secrets in logs.** | None logged | Log only `request_id`, a short device-id prefix, the action, and the result. Never log keys, full messages, or attestation blobs. | Log review checklist per phase |

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
  gnome-keyring (and would not unlock an ecryptfs home). Phase 7 documents the
  impact. The login path may stay password-only.
- **R‑5 App-level UI deception.** A malicious app update could show false text
  before the BiometricPrompt. The signed `AUTH_REQUEST` limits what it could
  sign to real requests from the paired verifier. Supply-chain security of
  builds is out of scope for the MVP.
- **R‑6 Biometric spoofing.** PhoneKey inherits the phone's Class 3 biometric
  false-accept rate and spoof resistance.
- **R‑7 Advertisement fingerprinting.** The laptop advertises the PhoneKey
  service UUID, which reveals that PhoneKey is installed. It reveals no identity.

## 7. Security-sensitive decisions (need explicit sign-off)

| ID | Decision | Choice | Trade-off |
|---|---|---|---|
| D‑1 | Pairing authenticity | BLE LESC Numeric Comparison, with app keys exchanged inside the authenticated link | Uses the standard Bluetooth mechanism with no extra dependencies. It relies on the BT stacks' LESC implementations and on the user comparing codes. Alternative: QR code with a one-time secret. |
| D‑2 | Where signatures are verified | In `phonekeyd` (Python), not in the C PAM module | Keeps the C code in root processes tiny, with no crypto or parsing. The daemon is fully trusted, but it holds nothing more sensitive than PAM itself. |
| D‑3 | Key security level | StrongBox **detected at runtime** with TEE fallback. **Software keys are refused.** | The test device (Motorola Edge 50 Plus) may not have StrongBox. TEE is still hardware-isolated. |
| D‑4 | `setUnlockedDeviceRequired(true)` | On by default | Safer, because a locked phone never signs. But the user may need to unlock the phone *and then* pass BiometricPrompt, which is two steps. To be re-evaluated on the real device in Phase 1. Turning it off needs your approval. |
| D‑5 | Attestation | **Informational only.** Recorded and displayed, never required. | Not requiring it means the verifier cannot prove the key is hardware-backed. It relies on the app's own check (D‑3). |
| D‑6 | Biometric class | `BIOMETRIC_STRONG` only, no device-credential fallback in the prompt | Face unlock on many phones is Class 1/2 and won't work. After a lockout the user falls back to the laptop password. |
| D‑7 | Daemon privilege | Dedicated `phonekey` system user in group `bluetooth`, not root | Needs a BlueZ D-Bus policy check in Phase 3. If BlueZ requires root for GATT registration, this is re-raised before any change. |
| D‑8 | PAM placement | `auth sufficient pam_phonekey.so` added to **one service file** (`/etc/pam.d/sudo` first) before `@include common-auth`. `common-auth` is never edited. | Limits the blast radius. Each service is enabled explicitly. |
| D‑9 | Replay state in memory only | Yes | A restart invalidates in-flight requests, which is the safe direction. |
| D‑10 | Optional hardening: BlueZ `SecureConnections = only` in `/etc/bluetooth/main.conf` | **Not applied** in the MVP | It would prevent legacy pairing system-wide, which could affect your other BT devices. Changing it needs explicit approval. |

## 8. Platform constraints

### 8.1 Android Keystore / BiometricPrompt

- Per-use auth (timeout 0) **requires** `BiometricPrompt.CryptoObject(signature)`.
  Calling `sign()` without it throws. The Phase 1 tests exercise this.
- `AUTH_BIOMETRIC_STRONG` accepts only Class 3 sensors. Motorola Edge 50 Plus:
  the under-display fingerprint sensor is expected to be Class 3, and face
  unlock probably is not. This will be verified in Phase 1 with
  `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)`.
- StrongBox supports only P‑256 EC (which we use), and it is slower (hundreds of
  ms per signature). `StrongBoxUnavailableException` → retry TEE-backed.
- `setInvalidatedByBiometricEnrollment(true)` → `KeyPermanentlyInvalidatedException`
  after enrollment changes, and the phone must be re-paired.
- Private keys are non-exportable: `PrivateKey.getEncoded()` returns `null`,
  and no API returns key material. The Phase 1 tests check this.
- `KeyInfo.getSecurityLevel()` needs API 31, so **minSdk = 31** (Android 12).
  That also matches the modern BLE permission model (`BLUETOOTH_CONNECT`,
  `BLUETOOTH_SCAN`).
- Background BLE needs a foreground service (`connectedDevice` type on
  API 34+) and a visible notification. Some vendors kill background services
  aggressively, so a battery-optimization exemption may be requested.
- A BiometricPrompt needs an Activity in the foreground. An incoming request
  therefore raises a high-priority notification / full-screen intent that opens
  the request screen.

### 8.2 Linux Mint / BlueZ / PAM

- BlueZ 5.72 over D-Bus: `GattManager1` (GATT server), `LEAdvertisingManager1`
  (4 instances), `AgentManager1` (pairing agent). The adapter supports both
  central and peripheral roles.
- `sudo` runs PAM as **root**. `cinnamon-screensaver` runs PAM **as the
  logged-in user**. The daemon socket must therefore be connectable by users,
  and must authorize requests by SO_PEERCRED uid.
- `cinnamon-screensaver` may only start PAM after a keypress or password
  submission. How to trigger PhoneKey on the lock screen is an open question
  for Phase 6.
- `lightdm` (slick-greeter) login: PhoneKey cannot provide the password that
  gnome-keyring and ecryptfs need (R‑4).
- `/etc/pam.d/common-auth` is shared by nearly every service, so PhoneKey
  **never** edits it.

## 9. Recovery procedures

These work **without the phone** and **without `phonekeyd` running**.

1. **Normal fallback.** If PhoneKey is unavailable, times out, or is denied, the
   next module in the stack (`pam_unix`) asks for your password as usual.
2. **Disable PhoneKey** (Phase 5+): `sudo phonekey disable`. This restores the
   pristine PAM files from `/var/backups/phonekey/` and removes the
   `pam_phonekey.so` lines.
3. **Revoke a phone:** `sudo phonekey unpair <device-id-prefix>` (or
   `--all`). This deletes the registry entry. Also remove the BLE bond:
   `bluetoothctl remove <address>`.
4. **Manual recovery** if the `phonekey` CLI is broken:
   `sudo sed -i '/pam_phonekey\.so/d' /etc/pam.d/sudo` (and any other enabled
   service file), then `sudo systemctl disable --now phonekeyd`.
5. **If sudo itself is broken:** Linux Mint locks the root password by
   default, so `su -` is usually not an option. Instead, boot **recovery mode**
   from the GRUB menu (Advanced options → recovery mode → root shell), run
   `mount -o remount,rw /`, then apply step 4.
   **Before enabling PhoneKey for sudo, open a separate root shell and keep it
   open until you have verified sudo works both with and without the phone.**

Phase 6 (screen unlock) and Phase 7 (login) will add procedures specific to
their PAM files before they are enabled.

## 10. Rules for contributors

- Never use or invent custom crypto primitives, and never commit keys, test
  credentials, or `*.jks` files.
- Never log secrets or full protocol messages.
- Never make PhoneKey `required`/`requisite`, and never edit `common-auth`.
- Never change PAM or system configuration without an explicit confirmation
  step that shows the exact diff and the recovery path.
- Every new threat or decision goes into this document before its code.
