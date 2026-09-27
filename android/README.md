# PhoneKey — Android authenticator

Kotlin app, minSdk 31 (Android 12), no third-party dependencies beyond
`androidx.appcompat` and `androidx.biometric`.

**Current state: Phase 1, a local crypto prototype.** No BLE, no pairing, no
network. The app can:

1. Generate an ECDSA P‑256 signing key in Android Keystore. StrongBox is tried
   first if the phone advertises it, otherwise the key goes in the TEE.
   Software-only keys are refused.
2. Keep the private key inside Keystore. It is non-exportable.
3. Expose the public key (DER SubjectPublicKeyInfo) and its id,
   `SHA-256(SPKI)`.
4. Require a fresh Class 3 biometric through `BiometricPrompt` + `CryptoObject`
   for **every** signature.
5. Sign a random 32-byte test challenge, then verify it with the public key,
   and show that a modified challenge or signature is rejected.

## Layout

```
app/src/main/java/dev/phonekey/authenticator/
  crypto/DeviceKeyStore.kt      Keystore key policy (the only way keys are created)
  crypto/SignatureVerifier.kt   P-256 SPKI parsing, ECDSA verify, key ids, challenges
  biometric/BiometricSigner.kt  BiometricPrompt bound to a Keystore Signature
  ui/MainActivity.kt            Phase 1 test screen
app/src/test/…                  JVM unit tests (verification logic)
app/src/androidTest/…           Instrumented tests (real Keystore policy, on the phone)
```

## Build and test

```bash
cd android
./gradlew assembleDebug            # build app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest        # JVM tests, no phone needed
./gradlew connectedDebugAndroidTest   # on a USB-connected phone (see below)
./gradlew installDebug             # install the test app
```

`local.properties` (gitignored) must point to the SDK:
`sdk.dir=/home/<you>/Android/Sdk`. Android Studio creates it automatically.

> On networks with broken IPv6, Gradle's JVM may fail to download
> dependencies. Run with
> `GRADLE_OPTS=-Djava.net.preferIPv4Stack=true ./gradlew -Dorg.gradle.jvmargs="-Xmx2g -Djava.net.preferIPv4Stack=true" …`.

### Phone requirements for the instrumented tests and the app

- USB debugging enabled (Settings → About phone → tap *Build number* 7× →
  Developer options → USB debugging).
- A screen lock and **at least one fingerprint** enrolled. Keystore refuses to
  create biometric-bound keys otherwise, and the device-key tests are
  *skipped* (not failed) when no Class 3 biometric is available.

### What the tests prove

| Requirement | Test |
|---|---|
| Valid signature verifies | `SignatureVerifierTest.validSignatureVerifies`, `KeystorePolicyTest.keystoreSignaturesVerifyAndTamperingIsDetected` |
| Modified challenge fails | `SignatureVerifierTest.modifiedChallengeFails` (every byte), instrumented tamper test |
| Modified signature fails | `SignatureVerifierTest.modifiedSignatureFails` (every byte), `malformedSignatureFailsWithoutThrowing` |
| Signing impossible without biometric | `KeystorePolicyTest.signingWithoutBiometricIsRefused` (with a no-auth control key proving the policy is the cause), `keyRequiresFreshStrongBiometricForEverySignature` |
| Private key not exportable | `KeystorePolicyTest.privateKeyCannotBeExported` (`getEncoded() == null`, PKCS#8 export throws) |
| Hardware-backed, StrongBox → TEE fallback | `deviceKeyIsHardwareBacked`, `teeFallbackWhenStrongBoxAbsent` |
| Wrong key / wrong curve / malformed key rejected | `signatureFromAnotherKeyFails`, `nonP256KeysAreRejected`, `malformedSpkiIsRejected` |

The **successful** biometric-gated signature can't be automated, because it
needs a real finger. It is tested manually in the app: **Generate test key** →
**Sign test challenge**. After touching the sensor, all three lines should show
✓. **Try signing without biometric** must report that Keystore refused.

## Android Keystore / BiometricPrompt constraints and limitations

- **StrongBox is optional.** It is detected through
  `FEATURE_STRONGBOX_KEYSTORE`. If it is absent, or generation throws
  `StrongBoxUnavailableException`, the key is created in the TEE. Both are
  hardware-isolated. StrongBox is a separate secure chip, and is slower.
- **Software keys are refused** (`KeyInfo.securityLevel == SOFTWARE`).
  `SECURITY_LEVEL_UNKNOWN_SECURE` is treated as TEE.
- **Attestation is informational.** It is requested with a random challenge.
  If generation with attestation fails, the key is regenerated without it
  (SECURITY.md D‑5).
- **Per-use authentication** (timeout 0, `AUTH_BIOMETRIC_STRONG`). An unlocked
  phone is not enough, and neither is a recent unlock. Each signature needs its
  own `BiometricPrompt` success bound to the `Signature` object.
- **Only Class 3 biometrics.** Many phones' face unlock is Class 1/2 and is not
  offered. There is no PIN/pattern fallback in the prompt, by design (D‑6).
- **Enrollment changes invalidate the key** (`KeyPermanentlyInvalidatedException`).
  Adding a new fingerprint means generating a new key (in later phases:
  re-pairing).
- **No `setUnlockedDeviceRequired`** (D‑4, turned off after device testing).
  With it, keys stayed sealed after a face unlock (Keystore: "super decryption
  key is not in memory"), so PhoneKey failed on an unlocked phone. The
  per-signature fingerprint remains the authorization.
- **ECDSA signatures are malleable**: anyone can turn a valid `(r, s)` into
  another valid `(r, n−s)`. PhoneKey never uses signature bytes as identifiers.
  Replay protection comes from single-use challenges.
- **No biometric data** is ever visible to the app. It only receives the
  success/error callback from the OS.

## Device report

Phase 1 results on the test phone (2026-09-27).

| Field | Motorola Edge 50 Fusion |
|---|---|
| Android / API | 16 / 36, security patch 2026-07-01, verified boot green |
| StrongBox feature | **No.** `FEATURE_STRONGBOX_KEYSTORE` absent; KeyMint v3 in the TEE |
| Key security level obtained | **TEE** (fallback path exercised) |
| Attestation available | Yes, a 5-certificate chain (informational only) |
| Class 3 biometric | Yes (fingerprint) |
| Exception when signing without biometric | `SignatureException` ← `KeyStoreException: Key user not authenticated` (`KEY_USER_NOT_AUTHENTICATED`, "No operation auth token received"). This is enforced by keystore2/KeyMint, not by app code. |
| Instrumented tests | 7/7 pass (`scripts/android-device-tests.sh`) |
| Manual flow (generate → biometric sign → verify, tamper checks, unauthorized sign) | All pass, as reported by the tester on the device |

### Known tooling issue

`./gradlew connectedDebugAndroidTest` (AGP 9.4.1) exits with "There were
failing tests" even though its own report shows 7/7 passed and the raw
instrumentation result is `OK (7 tests)`. Use
[`scripts/android-device-tests.sh`](../scripts/android-device-tests.sh)
instead. It runs `am instrument` directly and fails unless the suite reports
`OK`.
