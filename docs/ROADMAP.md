# PhoneKey — Roadmap

This is the development plan, from the completed MVP phases through to public
alpha and Linux login. It replaces the short phase table that used to be in
[ARCHITECTURE.md §5](ARCHITECTURE.md#5-phase-plan). Security decisions stay in
[../protocol/SECURITY.md §7](../protocol/SECURITY.md) (D‑1…D‑20); this document
refers to them rather than restating them.

> PhoneKey is **pre-alpha and not production-secure**. Nothing in this roadmap
> is a promise of compatibility or security until a phase's acceptance
> criteria are met on real, named hardware and software.

**Last updated:** 2026-09-30.

## Contents

- [Status at a glance](#status-at-a-glance)
- [Roadmap decisions](#roadmap-decisions)
- [How to read a phase](#how-to-read-a-phase)
- Completed: [0](#phase-0--foundation-architecture-protocol-threat-model) ·
  [1](#phase-1--android-cryptographic-prototype) ·
  [2](#phase-2--linux-verifier) · [3](#phase-3--ble-transport) ·
  [4](#phase-4--end-to-end-authentication) · [5](#phase-5--pam--sudo) ·
  [6](#phase-6--cinnamon-screen-unlock)
- Planned: [7](#phase-7--reliability--resilience) ·
  [8](#phase-8--pairing-20--qr-assisted-pairing) ·
  [9](#phase-9--security-hardening) ·
  [10](#phase-10--android-ux--device-compatibility) ·
  [11](#phase-11--release-engineering--packaging) ·
  [12](#phase-12--linux-compatibility) ·
  [13](#phase-13--android-compatibility-matrix) ·
  [14](#phase-14--multi-device--multi-user-support) ·
  [15](#phase-15--protocol-generalization) ·
  [16](#phase-16--proximity--relay-attack-research) ·
  [17](#phase-17--independent-security-review) ·
  [18](#phase-18--public-alpha) ·
  [19](#phase-19--linux-login-lightdm) ·
  [20+](#phase-20--future-integrations)

## Status at a glance

| Phase | Name | Status | Touches system configuration? |
|---|---|---|---|
| 0 | Foundation: architecture, protocol, threat model | **Complete** (2026-09-27) | No |
| 1 | Android cryptographic prototype | **Complete** (2026-09-27) | No |
| 2 | Linux verifier | **Complete** (2026-09-27) | No |
| 3 | BLE transport | **Complete** (2026-09-27) | No (development daemon runs as the user) |
| 4 | End-to-end authentication (`phonekey test`) | **Complete** (2026-09-27) | No |
| 5 | PAM + sudo | **Complete** (2026-09-29) | Installs the service; edits `/etc/pam.d/sudo` **after explicit confirmation** |
| 6 | Cinnamon screen unlock | **Complete** (2026-09-29) | Edits `/etc/pam.d/cinnamon-screensaver` **after explicit confirmation** |
| 7 | Reliability & resilience | Next | No new PAM changes |
| 8 | Pairing 2.0 / QR-assisted pairing | Planned | No |
| 9 | Security hardening | Planned | No |
| 10 | Android UX & device compatibility | Planned | No |
| 11 | Release engineering & packaging | Planned | Package install/uninstall (confirmed) |
| 12 | Linux compatibility | Planned | Per tested distribution, confirmed |
| 13 | Android compatibility matrix | Planned | No |
| 14 | Multi-device / multi-user | Planned | No |
| 15 | Protocol generalization | Planned | No |
| 16 | Proximity / relay-attack research | Research | No |
| 17 | Independent security review | Planned | No |
| 18 | Public alpha | Planned | No |
| 19 | Linux login (LightDM) | **Deliberately late** (D‑17) | Edits the display manager's PAM file **after explicit confirmation** |
| 20+ | Future integrations | Open | — |

**Renumbering note.** The Phase 0 plan had seven implementation phases, with
"Phase 7 — Login (`lightdm`), if practical" last. On 2026-09-30 the roadmap was
extended: login moved to **Phase 19**, and Phase 7 became reliability. Older
commit messages and notes that say "Phase 7 (login)" mean today's Phase 19.

## Roadmap decisions

These shape the order of the phases. Each is recorded (or already was) in the
security decision log so it cannot be changed silently.

| # | Decision | Where recorded |
|---|---|---|
| 1 | **Linux login remains one of the last major implementation phases** (Phase 19). | SECURITY.md **D‑17** |
| 2 | **Reliability comes before adding more authentication surfaces** (Phase 7 first). | SECURITY.md **D‑18** |
| 3 | **QR pairing first complements authenticated BLE pairing** (LE Secure Connections numeric comparison); it does not silently replace it. QR + Just Works is a security-model change needing its own decision. | SECURITY.md **D‑19**, D‑1 |
| 4 | **BLE proximity is not cryptographic distance bounding.** | SECURITY.md §2, R‑1 |
| 5 | **Relay attacks remain a residual threat.** | SECURITY.md R‑1 |
| 6 | **StrongBox is detected at runtime; its availability is never assumed.** | SECURITY.md D‑3 |
| 7 | **TEE-backed Android Keystore is an acceptable fallback** when StrongBox is unavailable (software keys are refused). | SECURITY.md D‑3 |
| 8 | **Biometric data stays on the Android device.** PhoneKey only learns that BiometricPrompt succeeded. | SECURITY.md G‑4 |
| 9 | **The Linux verifier never needs biometric data**; it verifies signatures only. | SECURITY.md G‑1, G‑4 |
| 10 | **Password and system recovery must remain available.** PhoneKey is always `sufficient`, never `required`, and can be disabled without the phone. | SECURITY.md G‑7, G‑8, §9 |
| 11 | **The PAM module stays a small trust-boundary shim**; cryptography and security logic live in `phonekeyd`. | SECURITY.md D‑2, D‑12 |
| 12 | **The protocol stays transport-agnostic and authorizes an action on a resource**, not "unlock Linux". | SECURITY.md **D‑20**, PROTOCOL.md intro |

## How to read a phase

Every phase uses the same sections: **Goal, Scope, Non-goals, Acceptance
criteria, Security considerations, Deliverables, Exit criteria.**

- **Completed phases (0–6)** keep their status. Their acceptance criteria are
  written after the fact and cite the evidence (tests, live checks) that
  already exists. They are not reopened.
- **Planned phases** describe intent. A criterion is met only by a test,
  a recorded live check on named hardware, or a documented decision.
- **Proposed target** marks a number that is a starting point to be confirmed
  or adjusted during the phase, not a promise.

---

## Completed phases

### Phase 0 — Foundation: architecture, protocol, threat model

**Status: Complete (2026-09-27).**

#### Goal
Decide the architecture and protocol, and write the threat model, before any code.

#### Scope
Environment inspection; [PROTOCOL.md](../protocol/PROTOCOL.md);
[SECURITY.md](../protocol/SECURITY.md); [ARCHITECTURE.md](ARCHITECTURE.md);
[ENVIRONMENT.md](ENVIRONMENT.md); license, README, repository layout.

#### Non-goals
Any code, package installation, or system configuration change.

#### Acceptance criteria
- Protocol, threat model (T‑1…T‑14), residual risks and decisions documented.
- Every threat maps to a mechanism and a named (then future) test.
- No system changes made.

#### Security considerations
Established the rules later phases follow: no invented cryptography, no
biometric data off the phone, password fallback always kept, and no PAM change
without explicit confirmation.

#### Deliverables
The documents above.

#### Exit criteria
Documents reviewed and Phase 1 approved.

### Phase 1 — Android cryptographic prototype

**Status: Complete (2026-09-27).**

#### Goal
Prove a hardware-held, biometric-gated signing key on the test phone.

#### Scope
Android Keystore P‑256 key with StrongBox detection and TEE fallback;
per-use `BIOMETRIC_STRONG` authentication; BiometricPrompt with a CryptoObject;
local sign and verify; codec and signature tests.

#### Non-goals
Bluetooth, the Linux side.

#### Acceptance criteria (met)
- Keys are hardware-backed; software keys are refused; private keys are not exportable.
- Signing without a fresh biometric is refused by Keystore.
- Test phone (Motorola Edge 50 Fusion) characterized: no StrongBox, TEE keys, Class 3 fingerprint.
- Evidence: `KeystorePolicyTest` (on-device), `SignatureVerifierTest`, codec vector tests.

#### Security considerations
StrongBox is never assumed (D‑3). Attestation is informational only (D‑5).

#### Deliverables
Android app skeleton, key store, biometric signer, tests.

#### Exit criteria
On-device tests pass, and the results are recorded in android/README.md.

### Phase 2 — Linux verifier

**Status: Complete (2026-09-27).**

#### Goal
A Linux verifier library and CLI that issue and verify challenges correctly.

#### Scope
Strict TLV codec; verifier key; paired-device registry; single-use pending
challenges with a TTL; pairing verification; simulator; shared test vectors;
`phonekey` CLI.

#### Non-goals
Bluetooth, PAM.

#### Acceptance criteria (met)
- Replay, tampering, unknown device, expiry, wrong label and version are rejected.
- Python and Kotlin both pass the shared vectors (`protocol/test-vectors/v1.json`).
- The security checks were mutation-tested: all 15 disabled checks were caught.
- Evidence: `test_verifier`, `test_pairing`, `test_codec`, `test_codec_fuzz`.

#### Security considerations
Replay state lives in memory only (D‑9).

#### Deliverables
`linux/daemon/phonekey/` library, CLI, tests, vectors.

#### Exit criteria
Test suite green; simulated end-to-end run passes.

### Phase 3 — BLE transport

**Status: Complete (2026-09-27).**

#### Goal
Carry protocol messages between phone and laptop over an authenticated BLE link.

#### Scope
As built: **phone = BLE peripheral, laptop = central** (roles swapped from the
Phase 0 plan because the laptop's controller cannot advertise, D‑11); framing;
LESC numeric-comparison bonding through PhoneKey's own scoped agent (D‑1);
the laptop's own L2CAP LE ATT link; keepalive.

#### Non-goals
PAM, system installation.

#### Acceptance criteria (met)
- Pairing completes with numeric comparison on both sides.
- The link requires an authenticated bond (`BT_SECURITY_HIGH`; phone-side MITM-only attributes).
- The link recovers after an app restart.
- Evidence: `test_framing`, `test_att`, `test_core`; live pairing on the test devices.

#### Security considerations
Just Works, PIN and passkey pairing are rejected. The agent is never the
default agent. MAC addresses and RSSI are never trusted.

#### Deliverables
`ble.py`, `att.py`, `framing.py`, `core.py`, `daemon.py`; Android `PhoneKeyService`.

#### Exit criteria
Live pairing and messaging work on the test hardware.

### Phase 4 — End-to-end authentication

**Status: Complete (2026-09-27).**

#### Goal
`phonekey test`: a real request approved with a fingerprint on the phone.

#### Scope
Request display on the phone, including over the lock screen; approval and
denial paths; keepalive and reconnect.

#### Non-goals
PAM.

#### Acceptance criteria (met)
- Live test A (phone unlocked) and test B (phone locked, one fingerprint over the lock screen) pass.
- Denial and timeout fail closed.
- Evidence: live tests; `test_core` timeout and disconnect tests.

#### Security considerations
`setUnlockedDeviceRequired` turned off after on-device testing (D‑4); the
per-signature Class 3 fingerprint remains the authorization.

#### Deliverables
End-to-end flow; system-mode preparation (unit file, install and uninstall scripts).

#### Exit criteria
Live tests pass, and PAM work is approved.

### Phase 5 — PAM + sudo

**Status: Complete (2026-09-29).** Includes the follow-up work done in the
same phase: the sudo command shown on the phone (D‑13), start on boot and
after app updates (D‑14), local-presence check (D‑15), a security review with
fixes, and leaf-only attestation to keep the pairing reply small.

#### Goal
Approve `sudo` with the phone while the password always keeps working.

#### Scope
`pam_phonekey.so` (thin C shim); `phonekey enable/disable`; the hardened
system service; installer.

#### Non-goals
Lock screen, login, `common-auth`.

#### Acceptance criteria (met)
- One `auth sufficient` line in `/etc/pam.d/sudo` only, shown as a diff, backed up, typed confirmation.
- Password fallback works for phone absent, denied, timeout, and daemon down.
- The sudo command is shown on the phone and signed; SSH, cron and background jobs are refused (password prompt).
- Recovery works without sudo (`pkexec phonekey disable`), and without the phone or the daemon.
- Evidence: `test_pam` (real libpam, also under ASan/UBSan), `test_pamconfig`, `test_presence`, `test_command`, `test_ipc`; live tests.

#### Security considerations
D‑2, D‑8, D‑12, D‑13, D‑15; residual risk R‑8.

#### Deliverables
PAM module, PAM editor, installer, documentation, recovery procedure (SECURITY.md §9).

#### Exit criteria
User verified sudo with and without the phone while a root shell was open.

### Phase 6 — Cinnamon screen unlock

**Status: Complete (2026-09-29).** A usability pass followed on 2026-09-30:
one-tap Deny, pairing progress, a clearer phone main screen, and a shorter message.

#### Goal
Unlock the Cinnamon lock screen with the phone.

#### Scope
`phonekey enable unlock` (20 s timeout); presence rule for the lock screen's
PAM helper; withdrawing the phone prompt when the laptop stops waiting.

#### Non-goals
Login screen; other desktops.

#### Acceptance criteria (met)
- Waking the locked screen asks the phone. Deny, a 20 s timeout, or a phone that is not connected give the password box.
- The text-console recovery path was rehearsed before enabling (SECURITY.md §9).
- Evidence: `test_pamconfig` (screensaver file), `test_presence` (unlock rule), `test_core` (withdrawal), `AuthenticatorCoreTest`; live tests.

#### Security considerations
D‑16; residual risk R‑9. After a phone unlock, `pam_gnome_keyring` does not run.

#### Deliverables
Code, tests, SECURITY.md D‑16, R‑9, §9.

#### Exit criteria
User confirmed working unlock, deny, timeout and Bluetooth-off behaviour.

---

## Planned phases

### Phase 7 — Reliability & resilience

#### Goal
Make the existing sudo and screen-unlock integration dependable for sustained
daily use **before** any new authentication surface is added (D‑18).

#### What "reliable" means for PhoneKey
PhoneKey is reliable when, under every condition listed below, all four hold:

1. **Never worse than the password.** Every PhoneKey failure ends in the
   normal password prompt within a bounded time, and PhoneKey never blocks or
   hides that prompt beyond its configured timeout (35 s sudo, 20 s unlock).
2. **Self-healing.** Once the condition clears (phone back in range,
   Bluetooth on again, daemon restarted…), PhoneKey works again **without
   a reboot, re-pairing, or manual Bluetooth steps.**
3. **No stuck state.** No request outlives its TTL; nothing stays "busy";
   no stale connection, half-received message, or pairing window stays open;
   no deadlock between the daemon, PAM callers and the phone.
4. **Explainable.** Logs on both sides say what happened and why, without
   keys, signatures, full messages or other secrets.

**Proposed targets** (to confirm or adjust in this phase, based on measurements):

| Measure | Observed so far | Proposed target |
|---|---|---|
| Password prompt when no phone is connected | ≈15 ms (PAM harness, 2026-09-27) | < 1 s |
| Reconnect after the condition clears | 28–50 s (app restart, adapter reset) | ≤ 60 s every time; investigate ≤ 15 s |
| Daily-use soak without manual intervention | not measured | 7 consecutive days |
| Approved requests that succeed while connected | not measured | measure first; then set a target |

#### Scope
Characterize, fix and test the conditions below. Where a mechanism already
exists, the phase **verifies** it (it is not assumed to work).

| # | Condition | Existing starting point (to verify) |
|---|---|---|
| 1 | Laptop sleep / wake | Not tested |
| 2 | Phone sleep / wake (screen off, Doze) | Not tested systematically |
| 3 | Phone reboot | Auto-start on boot (D‑14); not tested |
| 4 | Linux reboot | Service starts at boot (observed once) |
| 5 | Bluetooth adapter restart / USB re-enumeration | Adapter switch within 5 s (observed once) |
| 6 | Bluetooth off / on (laptop) | Watchdog restarts scanning; not tested end-to-end |
| 7 | Android service or app restart, app update | Auto-start after update (observed) |
| 8 | Phone leaves BLE range and returns | Not tested |
| 9 | Phone temporarily unavailable (busy, radio contention) | Keepalive drops dead links; not tested |
| 10 | Battery saver / background restrictions / vendor killers | Not tested |
| 11 | Phone Bluetooth disabled / re-enabled | Service reopens its GATT server; not tested end-to-end |
| 12 | `phonekeyd` restart | Pending requests dropped (D‑9); not tested end-to-end |
| 13 | `phonekeyd` crash / recovery | `Restart=on-failure`; not tested |
| 14 | Stale connections | Keepalive (20 s) + hello timeout; tested with fakes |
| 15 | Stale or incomplete fragmented messages | 5 s reassembly timeout; tested with fakes |
| 16 | Malformed packets | Codec fuzz tests; IPC validation |
| 17 | Concurrent authentication requests | BUSY on both sides; `PromptGate` tests |
| 18 | Authentication timeout behaviour | Daemon TTL 30 s; PAM timeouts; tested |
| 19 | Repeated attempts | Phone rate limit 5/min; not tested end-to-end |
| 20 | Password fallback in every expected failure mode | `test_pam` covers the PAM side; end-to-end matrix missing |
| 21 | No authentication deadlocks | Not systematically tested |
| 22 | No permanently stuck Bluetooth or session state | Not systematically tested |
| 23 | Recovery without a full machine reboot | Not systematically tested |
| 24 | Useful diagnostic logging without secrets | T‑14 manual review only |

Known issues to address: the reconnect gap during pairing (23 s observed), and
BlueZ/NetworkManager classic-Bluetooth activity right after bonding.

#### Non-goals
New authentication surfaces (login, SSH); protocol changes other than
reliability fixes; new pairing UX.

#### Acceptance criteria
- A written **fault-injection test matrix** covers conditions 1–24. For each:
  the expected behaviour, how to reproduce it, and the recorded result on the
  test hardware (Linux Mint 22.3 laptop, Motorola Edge 50 Fusion).
- Every condition ends in either successful PhoneKey authentication or the
  password prompt within its timeout. No case needs a reboot, re-pairing, or
  manual Bluetooth commands to recover.
- Automated tests (fake transport and scheduler, PAM harness) cover every
  condition that can be simulated: 14–19 at least, plus daemon restart semantics.
- The proposed targets are measured and then confirmed or revised, with the numbers recorded.
- A soak period of daily use (proposed: 7 days) completes with issues logged and resolved or documented.
- Log review: no secrets in daemon, PAM or Android logs across the whole matrix (T‑14).

#### Security considerations
Reliability fixes must not weaken fail-closed behaviour. No retry may reuse a
challenge, and none may extend a request past its TTL. Recovery paths must not
add privileges. Diagnostic logging must follow T‑14.

#### Deliverables
Test matrix document with results; new automated tests; fixes; updated
troubleshooting notes in the READMEs.

#### Exit criteria
All 24 conditions pass or have a documented, accepted limitation; the soak is
complete; the user signs off on daily-use reliability.

### Phase 8 — Pairing 2.0 / QR-assisted pairing

#### Goal
Make pairing easier and harder to get wrong. The phone should bind to exactly
the laptop the user is looking at, without depending on the user comparing codes carefully (R‑3).

#### Design decision (D‑19)
QR pairing is meant to **improve application-level binding and pairing UX**.
The first secure implementation **keeps authenticated BLE pairing (LE Secure
Connections numeric comparison)**; QR is added on top, not in its place.

- **Option A — QR-assisted application binding + authenticated BLE pairing.**
  The laptop shows a QR code carrying its verifier identity (public-key
  fingerprint) and one-time pairing material. The phone accepts only a
  `PAIR_REQUEST` that matches. The BLE bond still uses numeric comparison.
  This strictly adds security. **This is the planned first implementation.**
- **Option B — QR + BLE Just Works.** It removes the code comparison, but the
  BLE link is then encrypted and **not** protected against a man-in-the-middle.
  An attacker in the middle still cannot forge approvals (they are signed), but
  could read request contents (host, account, sudo commands) and disrupt the
  link. It also breaks the current "authenticated bond required" rule
  (PROTOCOL.md §5.1; phone MITM-only attributes; `BT_SECURITY_HIGH`).
  **Option B is a security-model change.** It must not silently replace
  Option A. It needs its own recorded decision and sign-off.
- Android does not let ordinary apps use Bluetooth out-of-band (OOB) pairing
  (`createBondOutOfBand` is a system API), so a QR code cannot secure the BLE
  bond itself on Android today.

#### Scope
QR payload design (verifier identity, one-time secret, expiry, version); a
one-time pairing session with a short expiry; the laptop showing the QR code
and its own identity and fingerprint; the phone showing the verifier identity
before approval; prevention of QR replay and pairing races (single use, bound
to the pairing window, first valid response wins and closes the window, the
laptop shows the joining phone for confirmation); unpair, revoke and re-pair
flows; groundwork for more than one device (Phase 14); camera permission
requested only while scanning; offline QR generation on Linux (terminal
and/or window) and offline QR scanning on Android.

#### Non-goals
Option B; cloud or online services; replacing BLE bonding.

#### Acceptance criteria
- A protocol design note (PROTOCOL.md) specifies the QR payload and how it
  binds to `PAIR_REQUEST`/`PAIR_RESPONSE`. Standard primitives only; shared
  test vectors on both sides.
- A mismatched, expired or reused QR code is rejected, with tests on both sides.
- A pairing race (two phones, or a photographed QR code) cannot silently pair
  a second device: tests, plus the laptop-side confirmation of the joining phone.
- The numeric-comparison bond is still required; tests show that Just Works is still rejected.
- The camera permission is used only during scanning; the app works without it (falls back to today's flow).
- Revoke and re-pair work without leftover state on either side.

#### Security considerations
The QR code is a secret for the length of the pairing window (shoulder-surfing
and photos). Its expiry and single use limit exposure. Pairing still requires
root on the laptop. Any move towards Option B needs a separate decision.

#### Deliverables
Protocol note; implementation on both sides; tests and vectors; updated pairing docs.

#### Exit criteria
Option A pairing works live; R‑3 is re-assessed; the user approves the UX.

### Phase 9 — Security hardening

#### Goal
Systematically test and document every known attack class, fill gaps in the
threat model, and state residual risks plainly.

#### Scope
Each item needs an automated test, a recorded live check, or a documented
rationale for why it cannot be tested. Many are already covered by T‑1…T‑14;
this phase closes gaps and consolidates.

| Area | Items |
|---|---|
| Replay and freshness | replay, challenge reuse, duplicate messages, stale messages |
| Tampering | modified challenge, action, resource, device ID, verifier ID |
| Identity | wrong phone, unknown phone, revoked phone, re-pairing |
| Device state | stolen phone, locked phone, unlocked phone, biometric requirement, enrollment change, key invalidation |
| Input handling | malformed messages, fragmented-message attacks, oversized messages |
| Concurrency and lifecycle | concurrent requests, daemon restart |
| Radio | BLE MITM considerations, BLE spoofing, relay attacks |
| Endpoints | compromised Linux host, compromised Android device |
| Local system | secret/key exposure, filesystem permissions, Unix-socket authorization, PAM trust boundary, privilege-escalation attempts |

#### Non-goals
Claiming protection against a compromised host (out of scope, T‑7), or
proving physical distance (R‑1).

#### Acceptance criteria
- SECURITY.md's threat table covers every item above, with expected result,
  mechanism, and a test or rationale. "Compromised Android device" gets its own entry (it has none today).
- Tests exist for all items that can be automated; gaps are listed as residual risks.
- A permissions audit of every installed file, directory and socket matches ARCHITECTURE.md §2.
- A privilege-escalation review covers the daemon, PAM module, CLI (including `pkexec` use) and installer.
- The relay limitation stays documented as residual (R‑1). **No claim that BLE proximity proves physical distance.**

#### Security considerations
This phase *is* the security work. Residual risks are written down, not hidden.

#### Deliverables
Updated SECURITY.md; new tests; an audit checklist with results.

#### Exit criteria
No open high-severity finding without a fix or an accepted, documented risk.

### Phase 10 — Android UX & device compatibility

#### Goal
A production-quality phone experience that behaves predictably on real devices.

#### Scope
Foreground-service behaviour; background restrictions and battery
optimization (and guiding the user through vendor settings); persistent
connection and reconnection; Bluetooth permission handling; BiometricPrompt UX;
showing the action and resource being authorized; clear approved, denied,
cancelled and withdrawn states; "phone unavailable", pairing and revocation
states; key generation; key invalidation and re-pairing guidance; Keystore
failure handling; **runtime StrongBox detection with TEE-backed fallback**
(D‑3); biometric enrollment changes; Android version and vendor differences.

#### Non-goals
iOS; cloud features; non-biometric approval methods (D‑6).

#### Acceptance criteria
- Every state above has a defined screen or notification text and is reachable in a test or recorded manual check.
- StrongBox is never assumed. Devices with and without StrongBox both work, and the UI shows which is in use.
- Enrollment change → key invalidated → the user is told to re-pair; tested on a device.
- Keystore and biometric failures never crash the app, and never leave a request pending.
- Accessibility basics: text scaling, screen-reader labels for the approve and deny actions.

#### Security considerations
The UI must never display text that isn't in the signed request as if it were
(R‑5). Details stay hidden on the lock screen except inside the prompt itself (D‑13).

#### Deliverables
App updates, UX notes, device-behaviour notes.

#### Exit criteria
User sign-off on the UX; the Phase 13 test plan is ready.

### Phase 11 — Release engineering & packaging

#### Goal
Install, upgrade and remove PhoneKey safely, with traceable builds.

#### Scope
**Linux:** a `.deb` package first; installation, upgrade, uninstall;
rollback and recovery; the systemd service; installing the PAM module (never
enabling it automatically); permissions and ownership; configuration; logs;
clean removal; recovery when PhoneKey configuration is broken.
**Android:** release signing; release builds; versioning; shrinking and
obfuscation where appropriate; permission review; APK/AAB strategy;
reproducible or at least traceable builds.
**CI:** Linux tests, Android tests, protocol vectors, PAM tests (including
sanitizers), security tests, static analysis.

#### Non-goals
App-store publication; distributions other than Debian/Ubuntu-family (Phase 12).

#### Acceptance criteria
- **Uninstall and recovery can never leave the user locked out.** Removing the
  package removes or neutralizes every PhoneKey PAM line first (or refuses,
  with instructions), and the result is verified with sudo and the lock screen.
- Upgrades keep pairings and PAM state, or clearly migrate them. Downgrade/rollback is documented.
- Installing the package never enables PAM integration by itself.
- Release APKs are signed with a release key kept out of the repository; builds can be traced to a commit.
- CI runs on every change, and all test suites (including the PAM module under the sanitizers) must pass to merge.

#### Security considerations
Signing keys never enter the repository. Package scripts run as root, so they
must be reviewed like the PAM editor. Supply chain: pinned dependencies (R‑5).

#### Deliverables
Packaging, CI configuration, release process documentation.

#### Exit criteria
Clean install → enable → upgrade → disable → purge cycle verified on the
test laptop, with password login working throughout.

### Phase 12 — Linux compatibility

#### Goal
Know, from testing, where PhoneKey works beyond the MVP laptop.

#### Scope
Distributions: Ubuntu, Debian, Fedora, Arch Linux (and Linux Mint).
Desktops: Cinnamon, GNOME, KDE Plasma, COSMIC where practical. Sessions: X11 and
Wayland. Lock screens differ per desktop (each needs its own PAM investigation
and recovery rehearsal, as Phase 6 had). BlueZ versions and Bluetooth controllers.

#### Non-goals
Claiming compatibility because the code "should" work.

#### Acceptance criteria
- A compatibility matrix with three states: **supported** (tested end to end
  with recorded results), **experimental** (partially tested, known gaps), and
  **unsupported/untested**.
- Today's baseline: **supported** = Linux Mint 22.3, Cinnamon, X11, BlueZ 5.72,
  Realtek RTL8822CU. Everything else = untested.
- Every "supported" entry has pairing, sudo, unlock (where applicable), and recovery rehearsed.

#### Security considerations
Each PAM stack and lock screen has different trust properties (for example,
which user runs PAM, and whether there is a session or a terminal). Presence rules
(D‑15, D‑16) must be re-derived per environment, not copied.

#### Deliverables
Compatibility matrix; per-environment notes and recovery procedures.

#### Exit criteria
At least one additional distribution and one additional desktop reach
"supported", or are documented as blocked with reasons.

### Phase 13 — Android compatibility matrix

#### Goal
Characterize real Android devices and set the minimum Android version from evidence.

#### Scope
Vendors: Motorola, Google Pixel, Samsung, OnePlus, Xiaomi/Redmi, and older
supported devices. Per device: BLE peripheral capability, connection
stability, biometric capability and strength class, Android Keystore,
hardware-backed keys, StrongBox availability, background execution, battery
optimization, screen-off behaviour, reboot behaviour, Bluetooth restart behaviour.

#### Non-goals
Supporting devices without a Class 3 biometric, or without hardware-backed keys (D‑3, D‑6).

#### Acceptance criteria
- A device matrix with measured results (supported / experimental / unsupported).
- **The minimum Android version is justified by the implementation.** Today it
  is `minSdk 33` (Android 13), because the app uses `KeyInfo.getSecurityLevel`
  (API 31), the API 33 GATT-server notify call, and the notification runtime
  permission (API 33). The phase either confirms 33 or documents what lowering it would take.
- Vendor background-killing behaviour and required user settings are documented per vendor.

#### Security considerations
Devices whose biometric is not Class 3, or whose keys are not hardware-backed,
are refused, not downgraded.

#### Deliverables
Device matrix; vendor notes; minimum-version rationale.

#### Exit criteria
At least three vendors characterized, including one with StrongBox.

### Phase 14 — Multi-device / multi-user support

#### Goal
Several phones per machine, one phone for several machines, and several Linux users, with clear control.

#### Scope
Multiple phones per account; one phone paired with several machines (the
phone already keeps a key per verifier; untested at scale); device
identification and naming; device inventory; revocation and safe removal;
per-device permissions (for example, which actions each device may approve);
multiple Linux users and per-user policy; recovery.

#### Non-goals
Cloud sync of pairings; sharing one device key across machines.

#### Acceptance criteria
- Defined behaviour when several paired phones are connected: which is asked, and in what order. Tested.
- Revoking one device never affects another; tested.
- Per-user isolation: one user's phone can never approve another user's request; tested (extends T‑7).
- Inventory commands and screens show every device with its fingerprint, account and last use.

#### Security considerations
Each trusted device adds attack surface: any one of them can approve. Policy
must make this visible and limit it (per-device actions; easy revocation).

#### Deliverables
Registry and UI changes; tests; documentation of the trust implications.

#### Exit criteria
Two phones × two users × two machines tested on real hardware.

### Phase 15 — Protocol generalization

#### Goal
Keep the protocol centered on **"authorize this action on this resource"**
(D‑20), so future verifiers fit without redesign, and without overengineering now.

#### Scope
Review the action namespace (`linux.sudo`, `linux.unlock`, …), the resource
and detail fields, verifier identity, and transport assumptions against future
verifiers (SSH, servers, NAS, smart doors, IoT, other local services).
Versioning and extension rules.

#### Non-goals
Implementing any new integration.

#### Acceptance criteria
- PROTOCOL.md documents action naming, how the phone displays unknown actions,
  extension and versioning rules, and which parts are transport-specific (BLE binding, §6) versus generic.
- A paper exercise maps at least two future verifiers (for example SSH and a
  door lock) onto the protocol, and lists any changes they would need.
- No change is made only to anticipate integrations that don't exist yet.

#### Security considerations
Generalization must not weaken display integrity (the phone shows what it signs),
domain separation (labels), or replay protection.

#### Deliverables
Updated PROTOCOL.md; design note on future verifiers.

#### Exit criteria
Review complete; any protocol change is versioned with test vectors.

### Phase 16 — Proximity / relay-attack research

#### Goal
Understand, and write down honestly, what proximity PhoneKey can and cannot guarantee.

#### Scope
BLE proximity limits; RSSI limits; relay attacks and BLE forwarding;
latency-based approaches; UWB; NFC; hardware-assisted distance bounding.

#### Non-goals
Shipping a proximity mechanism in this phase; speculative security claims.

#### Acceptance criteria
- A research document with three clearly separated parts:
  1. **What PhoneKey guarantees today:** a fresh, biometric-gated signature from a
     registered key over a request the user saw. **Not** physical distance.
  2. **What it does not guarantee:** that the phone is near the laptop (relay, R‑1),
     or that RSSI means anything for security.
  3. **Possible future stronger mechanisms**, with their hardware requirements and limitations.
- Any proposal that moves forward becomes its own planned phase with its own decision.

#### Security considerations
This phase must not produce claims stronger than the evidence supports.

#### Deliverables
Research document; SECURITY.md R‑1 updated with its conclusions.

#### Exit criteria
Document reviewed; R‑1 is up to date.

### Phase 17 — Independent security review

#### Goal
An external review before anything is called production-ready.

#### Scope
Protocol; cryptographic implementation; key lifecycle; pairing; BLE transport;
PAM integration; privilege boundaries; daemon architecture; Unix-socket
authorization; Android Keystore use; biometric enforcement; replay protection;
revocation; recovery; the relay threat model.

#### Non-goals
Certification.

#### Acceptance criteria
- A reviewer independent of the development team completes the review.
- Every finding is documented, with its severity and resolution.
- **Critical and high findings are fixed, or they block release.** Accepted risks are recorded in SECURITY.md.

#### Security considerations
Reviewers get the full threat model and residual risks, not a curated subset.

#### Deliverables
Review report (or summary); fixes; updated SECURITY.md.

#### Exit criteria
No unresolved critical or high findings.

### Phase 18 — Public alpha

#### Goal
A release that others can try safely, with honest expectations.

#### Scope and acceptance criteria
All of the following exist and are current:

- documented installation;
- documented pairing;
- documented recovery;
- a known compatibility matrix (Phases 12, 13);
- the security model and threat model;
- limitations and known issues;
- a passing test suite in CI;
- release artifacts (package, signed APK);
- uninstall and recovery instructions;
- **a clear pre-production warning** (unless the Phase 17 review supports something stronger).

#### Non-goals
Stability guarantees; production-ready status.

#### Security considerations
Default configuration: nothing enabled in PAM until the user opts in, with the
recovery rehearsal shown before enabling.

#### Deliverables
Release notes, versioned artifacts, public documentation.

#### Exit criteria
Alpha published; channel for issue reports in place.

### Phase 19 — Linux login (LightDM)

**Deliberately late (D‑17). Do not move earlier.** Login is more sensitive
than sudo or screen unlock: it runs during boot and session start, depends on
the display manager and start-up ordering, and a mistake can lock the user
out of the desktop entirely. The earlier phases have to mature first.

#### Goal
Optionally log in with the phone at the LightDM greeter, without ever making
PhoneKey the only way in.

#### Scope
LightDM (Slick Greeter on Mint) PAM integration; behaviour at boot (Bluetooth
and daemon start-up ordering, phone not yet connected); session start;
gnome-keyring and other password-derived secrets (R‑4); multiple users at
the greeter.

#### Non-goals
Replacing the password; unlocking disk encryption; other display managers
(Phase 12).

#### Acceptance criteria
- LightDM integration via `auth sufficient`, added only through
  `phonekey enable login` with a diff, backup and typed confirmation.
- Correct PAM behaviour at login, including the account and session stacks that follow.
- Password fallback when: the phone is unavailable, Bluetooth is unavailable,
  the daemon is unavailable, the daemon crashed, the phone denies, or the request times out.
- Boot-time ordering and start-up dependencies documented and tested (cold boot, warm reboot, resume).
- Login-session behaviour: the keyring outcome is decided and documented (R‑4).
- Lockout avoidance: recovery from a text console, and from GRUB recovery
  mode, rehearsed **before** enabling. A safe disable/uninstall path works without the phone.
- Recovery from a broken configuration is documented and tested.
- Multiple-user considerations: the greeter's user list and per-user pairing.
- A security review specifically covering login.
- **PhoneKey is never the only recovery path; normal password and system recovery stay available.**

#### Security considerations
The highest-risk integration in the roadmap. The greeter runs as a system user
before any user session exists, so presence rules (D‑15, D‑16) do not transfer
and need their own analysis.

#### Deliverables
Integration, tests, recovery procedure (SECURITY.md §9), decision entry.

#### Exit criteria
User sign-off after the rehearsal and a period of daily use, with the password
login path verified throughout.

### Phase 20+ — Future integrations

After Linux login is stable, the protocol (Phase 15) leaves room for other
verifiers, for example: SSH authentication, server authentication, NAS, smart
locks, IoT devices, and other local authorization services. **Nothing is promised
here yet.** Each integration will get its own phase, with scope, a threat
analysis and acceptance criteria, when it is taken on.
