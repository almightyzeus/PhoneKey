# PhoneKey Protocol — version 1 (draft)

Status: **draft, pre-alpha.** Nothing here has been security-reviewed by a third
party. Do not rely on it to protect anything of value.

This document defines the PhoneKey authorization protocol independently of any
particular verifier platform. The MVP implements an **Android authenticator**
and a **Linux verifier** over **Bluetooth Low Energy**, but nothing in the
message layer assumes Linux, PAM, or BLE.

Conceptually every exchange is:

```
Verifier:      "Authorize ACTION on RESOURCE for ACCOUNT"   (signed by verifier)
                 │
Authenticator:  shows the request to the user
                 │  user passes a strong biometric check
                 │  biometric unlocks one use of a hardware-held private key
                 ▼
                signs the exact request bytes
                 │
Verifier:       verifies the signature with the registered public key,
                checks the challenge is fresh and unused → decision
```

---

## 1. Terminology

| Term | Meaning |
|---|---|
| **Authenticator** | The device that holds the signing key and the user's biometric (MVP: Android app). |
| **Verifier** | The device that wants to authorize an action (MVP: Linux daemon `phonekeyd`). |
| **Device key** | ECDSA P‑256 key pair generated in Android Keystore, one per pairing. Private half never leaves Keystore. |
| **Verifier key** | ECDSA P‑256 key pair generated on the verifier, one per verifier installation. Used to sign requests so the authenticator only prompts for known verifiers. |
| **SPKI** | DER-encoded `SubjectPublicKeyInfo` of a public key (uncompressed point). |
| `device_id` | `SHA-256(SPKI of device key)` — 32 bytes. The authenticator's identity *for one verifier*. |
| `verifier_id` | `SHA-256(SPKI of verifier key)` — 32 bytes. |
| **Pairing** | One-time ceremony that registers the device key with the verifier and the verifier key with the authenticator. |
| **Assertion** | A signed `AUTH_RESPONSE`. |

Key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

## 2. Cryptographic choices

No custom cryptographic primitives are used. Everything is a standard
algorithm through a standard API.

| Purpose | Algorithm | Linux API | Android API |
|---|---|---|---|
| Device key signatures | ECDSA P‑256 / SHA‑256, DER signature | `cryptography` (`ec.ECDSA(hashes.SHA256())`) | `Signature("SHA256withECDSA")` over an `AndroidKeyStore` key |
| Verifier key signatures | ECDSA P‑256 / SHA‑256, DER signature | same | `Signature("SHA256withECDSA")` (verify only) |
| Identifiers, hashes | SHA‑256 | `hashlib` | `MessageDigest("SHA-256")` |
| Randomness | CSPRNG | `os.urandom` / `secrets` | `SecureRandom` |
| Link confidentiality & pairing authenticity | Bluetooth LE Secure Connections (P‑256 ECDH + AES‑CCM), Numeric Comparison | BlueZ | Android Bluetooth stack |

P‑256 was chosen over Ed25519 because every Android Keystore implementation
(TEE and StrongBox) supports it, which Ed25519 does not.

**Domain separation.** Every signature covers a fixed ASCII label ending in a
NUL byte, followed by the message bytes. Labels:

| Label | Signed by | Used in |
|---|---|---|
| `PhoneKey/v1/pair-request\0` | verifier key | `PAIR_REQUEST` |
| `PhoneKey/v1/pair-response\0` | device key | `PAIR_RESPONSE` |
| `PhoneKey/v1/auth-request\0` | verifier key | `AUTH_REQUEST` |
| `PhoneKey/v1/auth-assertion\0` | device key | `AUTH_RESPONSE` |

A signature valid under one label MUST NOT be accepted under another.

## 3. Message encoding

All messages use one deterministic binary encoding, so that "the bytes that
were displayed/verified" and "the bytes that were signed" are the same bytes.

### 3.1 Envelope

```
offset  size  field
0       2     magic      = 0x50 0x4B  ("PK")
2       1     version    = 0x01
3       1     type       (see §4)
4       …     fields     sequence of TLV fields
```

### 3.2 Fields (TLV)

```
tag   : u8
length: u16, big-endian
value : `length` bytes
```

Encoding rules. A receiver MUST reject the whole message (error `MALFORMED`)
if any rule is broken:

1. Tags appear in **strictly ascending** order. No tag may repeat.
2. Each message type has a fixed set of **required** and **optional** tags
   (§4). Unknown tags, or tags not allowed for that type, are rejected.
3. Each field has a fixed type and length limit (§3.3). Fixed-size fields
   MUST have exactly that size.
4. Integers are unsigned big-endian of the stated width.
5. Strings are strict UTF‑8 and are compared bytewise (no normalization).
   They MUST NOT contain control characters (U+0000–U+001F, U+007F–U+009F) or
   bidirectional formatting characters (U+061C, U+200E, U+200F,
   U+202A–U+202E, U+2066–U+2069). Strings are shown to the user in prompts,
   and bidi overrides could make the displayed text differ from what is
   signed.
6. There are no trailing bytes after the last field.
7. The total encoded message MUST NOT exceed **16 384 bytes**.
8. `signature` (tag `0x7F`), when present, is always the last field. The
   **signed bytes** are:

   `label || message bytes from offset 0 up to (not including) the signature TLV`

   The signature therefore covers the envelope header, the message type, and
   every other field.

### 3.3 Tag registry

| Tag | Name | Type | Size |
|---|---|---|---|
| 0x01 | `verifier_id` | bytes | 32 |
| 0x02 | `device_id` | bytes | 32 |
| 0x03 | `request_id` | bytes | 16 |
| 0x04 | `challenge` | bytes | 32 |
| 0x05 | `action` | string | 1–64 |
| 0x06 | `resource` | string | 1–256 |
| 0x07 | `account` | string | 1–64 |
| 0x08 | `issued_at` | u64 (Unix ms, verifier clock) | 8 |
| 0x09 | `ttl_ms` | u32 | 4 |
| 0x0A | `public_key` | bytes (SPKI DER, P‑256) | 91 |
| 0x0B | `display_name` | string | 1–64 |
| 0x0C | `pairing_nonce` | bytes | 32 |
| 0x0D | `request_hash` | bytes (SHA‑256) | 32 |
| 0x0E | `key_security` | u8 (`1` software, `2` TEE, `3` StrongBox) | 1 |
| 0x0F | `attestation_chain` | bytes (see §5.4) | 0–12 288 |
| 0x10 | `status` | u8 (see §4.5) | 1 |
| 0x11 | `error_code` | u16 (see §7) | 2 |
| 0x12 | `error_detail` | string (diagnostic only, never trusted or displayed as fact) | 0–128 |
| 0x13 | `detail` | string (what exactly is approved, e.g. a command line) | 1–256 |
| 0x7F | `signature` | bytes (DER ECDSA) | 8–72 |

Tags 0x14–0x7E are reserved for future versions. (`detail`, 0x13, was added in
the pre-alpha without a version bump: an older app rejects it as an unknown
tag, and the laptop then falls back to the password.)

Test vectors for the codec and for every signed message type will live in
[`test-vectors/`](test-vectors/). The Kotlin and Python implementations MUST
both pass them.

## 4. Message types

| Type | Name | Direction | Signed by |
|---|---|---|---|
| 0x01 | `PAIR_REQUEST` | verifier → authenticator | verifier key |
| 0x02 | `PAIR_RESPONSE` | authenticator → verifier | device key (new) |
| 0x03 | `AUTH_REQUEST` | verifier → authenticator | verifier key |
| 0x04 | `AUTH_RESPONSE` | authenticator → verifier | device key |
| 0x05 | `STATUS` | either | — (relies on link encryption) |
| 0x06 | `ERROR` | either | — (relies on link encryption) |

"R" = required, "O" = optional; any tag not listed is forbidden.

### 4.1 `PAIR_REQUEST` (0x01)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x01 | `verifier_id` | R | MUST equal SHA‑256(`public_key`). |
| 0x05 | `action` | R | Fixed: `phonekey.pair`. |
| 0x07 | `account` | R | Account on the verifier being bound (e.g. Linux username). |
| 0x08 | `issued_at` | R | |
| 0x09 | `ttl_ms` | R | Pairing window remaining. |
| 0x0A | `public_key` | R | Verifier public key. |
| 0x0B | `display_name` | R | Verifier name shown to the user (e.g. hostname). |
| 0x0C | `pairing_nonce` | R | 32 fresh random bytes. |
| 0x7F | `signature` | R | Verifier key, label `pair-request`. Proves the verifier holds the key. |

### 4.2 `PAIR_RESPONSE` (0x02)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x01 | `verifier_id` | R | Echo. |
| 0x02 | `device_id` | R | MUST equal SHA‑256(`public_key`). |
| 0x0A | `public_key` | R | New device public key. |
| 0x0B | `display_name` | R | Phone name shown on the verifier (metadata only). |
| 0x0C | `pairing_nonce` | R | Echo. |
| 0x0D | `request_hash` | R | SHA‑256 of the complete `PAIR_REQUEST` bytes (including its signature). |
| 0x0E | `key_security` | R | Security level the authenticator observed for its key. |
| 0x0F | `attestation_chain` | O | Informational; see §5.4. |
| 0x7F | `signature` | R | New device key, label `pair-response`. Proof of possession; producing it requires a biometric. |

### 4.3 `AUTH_REQUEST` (0x03)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x01 | `verifier_id` | R | |
| 0x02 | `device_id` | R | Which registered device key must answer. |
| 0x03 | `request_id` | R | 16 fresh random bytes. |
| 0x04 | `challenge` | R | 32 fresh random bytes. Never reused. |
| 0x05 | `action` | R | Machine-readable action, e.g. `linux.sudo`, `linux.unlock`, `linux.login`, `phonekey.test`. |
| 0x06 | `resource` | R | Human-readable target, e.g. `chinuZeus`. |
| 0x07 | `account` | R | Account being authorized, e.g. `chinuzeus`. |
| 0x08 | `issued_at` | R | Informational for the authenticator (clocks are not trusted to agree). |
| 0x09 | `ttl_ms` | R | Validity from receipt; the authenticator stops prompting after it. |
| 0x13 | `detail` | O | What exactly is approved, e.g. `sudo apt upgrade`. Written by the verifier itself (for sudo: from the requesting process), never taken from a client. Display-safe: no control or bidi characters; truncation is marked in the text (`… [+N more characters]`). |
| 0x7F | `signature` | R | Verifier key, label `auth-request`. |

### 4.4 `AUTH_RESPONSE` (0x04)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x01 | `verifier_id` | R | Echo. |
| 0x02 | `device_id` | R | Echo. |
| 0x03 | `request_id` | R | Echo. |
| 0x0D | `request_hash` | R | SHA‑256 of the complete `AUTH_REQUEST` bytes (including its signature). |
| 0x7F | `signature` | R | Device key, label `auth-assertion`. |

Because `request_hash` covers the whole request, the assertion binds the
challenge, action, resource, account, verifier, and device all at once. The
authenticator signs **only** after the user has seen those values and passed a
biometric check. There is no signed "deny": a refusal, cancellation, or
biometric failure is sent as an unsigned `ERROR`, and the verifier treats it the
same as "no approval".

### 4.5 `STATUS` (0x05)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x01 | `verifier_id` | O | |
| 0x02 | `device_id` | O | |
| 0x03 | `request_id` | O | When the status refers to a request. |
| 0x10 | `status` | R | `1` READY, `2` PROMPTING, `3` PAIRED, `4` BUSY. |

`STATUS` carries no security decision. It only drives the user interface and
liveness checks.

### 4.6 `ERROR` (0x06)

| Tag | Field | | Notes |
|---|---|---|---|
| 0x03 | `request_id` | O | When the error refers to a request. |
| 0x11 | `error_code` | R | §7. |
| 0x12 | `error_detail` | O | Diagnostic text. MUST NOT contain secrets. |

## 5. Pairing

Pairing establishes, in both directions, **which public key belongs to whom**.
Bluetooth addresses and device names are recorded only as metadata. They are
never an identity.

### 5.1 Transport pairing (BLE bond)

1. On the phone the user taps **Add computer**. For a bounded window (120 s)
   the authenticator advertises the **pairing UUID** (§6.1) instead of the
   service UUID.
2. The user runs `phonekey pair` on the verifier. For a bounded window
   (120 s) the verifier connects to phones advertising the pairing UUID, and
   only to those. Outside a pairing window it connects only to phones it is
   already bonded with.
3. The verifier bonds with the phone (`Device1.Pair`). Every PhoneKey
   attribute on the phone requires an **encrypted, MITM-authenticated** link
   (`PERMISSION_*_ENCRYPTED_MITM`), so only an authenticated bond works. Both
   stacks support LE Secure Connections, so this is **Numeric Comparison**:
   - Android shows its system pairing dialog with a 6-digit number,
   - the laptop's desktop Bluetooth agent (Blueman on Linux Mint) shows the
     number it received from BlueZ,
   - the user confirms on both sides only if the numbers match.

   PhoneKey registers **no** BlueZ agent of its own. If no agent is running,
   BlueZ falls back to unauthenticated "Just Works" pairing, the phone refuses
   access to its characteristics, and pairing fails safely.

### 5.2 Application pairing (key exchange)

Once the authenticated link is up:

```
Verifier                                            Authenticator
   │── PAIR_REQUEST {verifier key, account, name, nonce}  (signed) ─►│
   │                                                      verify signature,
   │                                                      verifier_id = H(pk),
   │                                                      show: "Pair with <name>
   │                                                             as <account>?"
   │                                                      user confirms
   │                                                      generate device key
   │                                                        (attestation challenge
   │                                                         = request_hash)
   │                                                      BiometricPrompt
   │◄── PAIR_RESPONSE {device key, request_hash, …}  (signed by new key)
   verify: signature, device_id = H(pk), nonce,
           request_hash, pairing window still open
   store device record
   │── STATUS {PAIRED} ───────────────────────────────────────────────►│
   leave pairing mode                                   store verifier record
```

The verifier stores:

```
device_id, public_key (SPKI), account, display_name, paired_at,
bond address (metadata), key_security, attestation summary (informational)
```

The authenticator stores:

```
verifier_id, verifier public_key, verifier display_name, account,
Keystore alias of the device key, bond address (metadata)
```

Both sides SHOULD show a short fingerprint of the other side's key (the first
8 bytes of the id, in hex, grouped) so the user can compare it later.

### 5.3 Device key generation (Android)

| Property | Value |
|---|---|
| Algorithm | EC `secp256r1`, purpose SIGN, digest SHA‑256 |
| Location | `AndroidKeyStore`. StrongBox is tried first (`setIsStrongBoxBacked(true)`); on `StrongBoxUnavailableException` the key is generated TEE-backed. StrongBox is never assumed. |
| Auth | `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`: **every** signature needs a fresh Class 3 biometric through `BiometricPrompt` + `CryptoObject`. |
| Enrollment change | `setInvalidatedByBiometricEnrollment(true)`: adding a fingerprint permanently invalidates the key, and the phone must be re-paired. |
| Device lock | **Not** `setUnlockedDeviceRequired` (SECURITY.md D‑4): the per-use fingerprint is the authorization |
| Attestation | `setAttestationChallenge(request_hash)` |
| One key per verifier | Yes: alias `phonekey.v1.<hex(verifier_id)[0:16]>` |

After generation the app reads `KeyInfo.getSecurityLevel()`. If the level is
`SOFTWARE` (or unknown), pairing is **refused** by the app. The observed level
is reported in `key_security`.

### 5.4 Attestation (informational in the MVP)

`attestation_chain` is the Keystore attestation certificate chain for the
device key. It is encoded as a sequence of `u16 length || DER certificate`,
leaf first. It is OPTIONAL. The authenticator SHOULD send **only the leaf
certificate**: it holds everything the verifier reads (security level and
challenge), and the full chain (about 3.3 KB) made the pairing reply large
enough to drop the BLE link on the MVP hardware.

For the MVP:

- The verifier MAY parse the chain and record a summary: the claimed security
  level, the attestation challenge match, and whether the chain ends in a known
  Google root.
- The verifier MUST NOT make pairing or authentication depend on the chain
  being present, parsable, or valid. A missing or failed chain produces a
  **warning** in `phonekey pair`/`phonekey devices` and nothing more.
- Revocation lists are not checked, because the design is offline and has no
  network access.

A future version may offer an opt-in policy that requires valid attestation.

The Linux verifier records a summary such as `TEE, bound to this pairing, leaf
certificate only, roots not verified`. It reads the Keystore security level and
checks that the attestation challenge equals this pairing's `request_hash`,
which shows the key was created for this pairing. It does not verify the chain
against Google's roots.

## 6. BLE transport binding

### 6.1 Roles and GATT layout

The authenticator (phone) is the **peripheral / GATT server**. The verifier
(laptop) is the **central / GATT client**. The roles were chosen this way
because some laptop controllers cannot advertise; the laptop of the MVP (a
Realtek RTL8822CU) rejects every LE advertisement. Roles have no security
meaning: identity and authorization rest only on signatures.

| Item | UUID | Properties on the phone |
|---|---|---|
| PhoneKey service | `eb109ed5-92be-4d34-a98d-61bb7f350b41` | primary |
| A2V characteristic (authenticator → verifier) | `f3c11509-8693-4342-ae5b-8d0f7e6e50fa` | indicate; CCCD read/write need an encrypted MITM link |
| V2A characteristic (verifier → authenticator) | `955060b9-442a-41f4-bea8-251ea1f42f85` | write (with response); needs an encrypted MITM link |
| Pairing advertisement | `419b7d95-95a6-441f-a103-eb24d90499e0` | advertised instead of the service UUID in pairing mode |

The phone advertises (connectable, no device name, no other data) only while a
paired verifier is not connected, or during pairing. Advertisements carry no
identity and no secret. The phone's address is a rotating private address; the
verifier recognises a bonded phone through the bond's identity resolving key.

### 6.3 Connection handshake

1. The verifier connects **over LE only**, bonds if needed, discovers the
   service, and subscribes to A2V indications. (The Linux verifier opens its
   own L2CAP LE socket to the phone's ATT channel for this. A generic
   "connect" on a dual-mode phone can pick classic Bluetooth and its
   profiles, which PhoneKey never uses.)
2. On subscription the phone sends `STATUS {READY}`:
   - with `verifier_id` and `device_id` if the laptop is a paired verifier
     (looked up by its Bluetooth address, which is only a routing hint), or
   - with no ids when the phone is in pairing mode, which asks the verifier
     for a `PAIR_REQUEST` if its own pairing window is open.
3. **Keepalive:** every 20 s the verifier sends `STATUS {READY, verifier_id}`,
   and the authenticator answers with its own `STATUS {READY}` with ids. If no
   `STATUS` arrives within 6 s (after subscribing, or after a keepalive), the
   verifier disconnects and reconnects. This recovers links that stay up while
   the phone app restarts.
4. The verifier uses the ids in `STATUS` only to route requests and show
   status. They are unauthenticated claims. A false claim can at most cause a
   request to be sent to the wrong phone, which then fails. The decision
   always rests on the device key's signature.

### 6.2 Framing

A PhoneKey message can be larger than one ATT write or indication, so each
message is split into frames:

```
byte 0  msg_no  u8   increments per message per direction (wraps)
byte 1  frag    u8   0, 1, 2, … within the message
byte 2  flags   u8   bit 0 = LAST; other bits MUST be 0
byte 3… payload      up to min(ATT_MTU − 3, 244) − 3 bytes
```

A frame (header + payload) never exceeds 244 bytes, even when the negotiated
ATT MTU is larger. That is one LE data PDU with Data Length Extension (251
bytes) minus the L2CAP and ATT headers. Larger frames were observed to make a
laptop controller (Realtek RTL8822CU) drop the link during bursts.

The receiver discards the partial message and sends `ERROR MALFORMED` when:

- a frame arrives out of order or with a different `msg_no` before LAST,
- the reassembled size would exceed 16 384 bytes,
- more than 255 fragments are needed, or
- LAST does not arrive within 5 s of the first fragment.

Frames are plain transport. Integrity comes from the message signatures, and
confidentiality from the LESC link encryption.

## 7. Error codes

| Code | Name | Meaning |
|---|---|---|
| 0x0001 | `MALFORMED` | Encoding or framing rule violated. |
| 0x0002 | `UNSUPPORTED_VERSION` | Unknown `version`. |
| 0x0003 | `UNKNOWN_VERIFIER` | `verifier_id` not paired with this authenticator. |
| 0x0004 | `UNKNOWN_DEVICE` | `device_id` not registered on this verifier. |
| 0x0005 | `BAD_SIGNATURE` | Signature did not verify. |
| 0x0006 | `EXPIRED` | Request TTL elapsed. |
| 0x0007 | `UNKNOWN_REQUEST` | `request_id` not pending (replay, duplicate, or late). |
| 0x0008 | `BUSY` | Another request is already in progress. |
| 0x0009 | `USER_DENIED` | User declined in the app. |
| 0x000A | `BIOMETRIC_FAILED` | Biometric cancelled, failed, or locked out. |
| 0x000B | `KEY_INVALIDATED` | Device key permanently invalidated (biometric enrollment changed); re-pair required. |
| 0x000C | `NOT_PAIRING` | Pairing message received outside a pairing window. |
| 0x000D | `RATE_LIMITED` | Too many requests. |
| 0x000E | `INTERNAL` | Unexpected internal failure. |
| 0x000F | `INSECURE_KEY` | Pairing refused: the device key is not hardware-backed (`key_security` = software). |

Every error is fail-closed: the requested action is **not** authorized.

## 8. Authentication

### 8.1 Verifier procedure

1. Receive a local authorization request `(account, action, resource)`.
2. Select the registered devices for `account` that are connected. If there
   are none, fail immediately with *unavailable*, and the caller falls back to
   its normal method (e.g. password).
3. Refuse if a request is already pending for that device (`BUSY`).
4. Generate `request_id` (16 B) and `challenge` (32 B) from the CSPRNG. Build
   and sign `AUTH_REQUEST`. Store in **memory only**:
   `request_id → {device_id, request_hash, deadline (monotonic clock)}`.
5. Send the request and wait until the deadline (default TTL 30 s).
6. On `AUTH_RESPONSE`, check **all** of the following:
   - the message decodes under §3,
   - `request_id` is pending, and remove it **immediately** (single use,
     whether the rest passes or not),
   - the monotonic clock is still before the deadline,
   - `verifier_id`, `device_id`, and `request_hash` equal the stored values,
   - the signature verifies with the stored public key of `device_id`, under
     label `auth-assertion`.
7. Success only if every check passes. Anything else — `ERROR`, timeout,
   disconnect, malformed data — is failure. Remove the pending entry in every
   terminal case.
8. If the local caller stops waiting before a result (the lock screen gives
   up, sudo is interrupted), remove the pending entry and send the
   authenticator `ERROR` with `error_code = EXPIRED` and that `request_id`, so
   it dismisses the prompt. A late `AUTH_RESPONSE` then fails as
   `UNKNOWN_REQUEST`.

### 8.2 Authenticator procedure

1. Decode the `AUTH_REQUEST` (§3). Reject `UNSUPPORTED_VERSION` or `MALFORMED`.
2. Look up `verifier_id`. If it is unknown, send `UNKNOWN_VERIFIER` and **do
   not prompt**.
3. Verify the verifier signature. If it fails, send `BAD_SIGNATURE` and **do
   not prompt**.
4. If `device_id` is not the key stored for that verifier, **ignore the request
   silently**. Another phone may be the addressee, and an `ERROR` from this
   phone would cancel that phone's pending request.
5. If a prompt is already showing, send `BUSY`. Apply a rate limit (default:
   at most 5 requests per verifier per minute).
6. Check that `account` equals the account stored at pairing, then show a
   notification or activity with the verifier name, `action`, `resource`,
   `account` and, when present, `detail`. Launch `BiometricPrompt` with a
   `CryptoObject` that wraps a `Signature` initialized with the device key.
   `detail` also goes into the prompt itself, because over the lock screen
   the prompt is all the user sees.
7. On biometric success, sign `AUTH_RESPONSE` and send it. On failure or
   cancel, send `BIOMETRIC_FAILED` / `USER_DENIED`. On
   `KeyPermanentlyInvalidatedException`, send `KEY_INVALIDATED`.
8. Dismiss the prompt if `ttl_ms` passes (measured from receipt), the link
   drops, or the verifier sends `ERROR` naming the prompt's `request_id` over
   the same link (§8.1 step 8). `ERROR` is unsigned, so it may only ever
   dismiss a prompt, never approve one.

### 8.3 Replay and freshness

- Challenges are 256-bit CSPRNG values. A collision is negligible.
- The pending table is the only thing that can make an assertion valid. An
  assertion whose `request_id` is not pending is rejected, whether it is
  replayed, duplicated, arrives late, or belongs to another session. The table
  is cleared when the verifier restarts, so assertions from before a restart
  are never valid.
- The verifier checks deadlines against its own monotonic clock, so it never
  needs to trust the authenticator's clock.
- ECDSA signatures are malleable: `(r, s)` and `(r, n−s)` both verify.
  Signature bytes are therefore never used as identifiers or replay keys. Only
  `request_id` and the pending table are.

## 9. Versioning

`version = 0x01`. A receiver MUST reject any other value with
`UNSUPPORTED_VERSION`. There is no in-band negotiation in v1. A future version
will define one, and every signature label includes the version to prevent
cross-version confusion.

## 10. Out of scope for v1

- Distance bounding or relay resistance (see SECURITY.md, residual risk R‑1).
- Multiple verifier accounts per pairing (pair once per account).
- Required attestation policies.
- Transports other than BLE, and verifiers other than Linux.
