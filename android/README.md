# PhoneKey — Android authenticator

Kotlin app, minSdk 31. Not yet created; this is Phase 1.

Phase 1 scope: generate a biometric-gated P-256 key in Android Keystore
(StrongBox detected at runtime, with TEE fallback), sign test challenges through
`BiometricPrompt` + `CryptoObject`, verify signatures locally, and add tests. No
BLE yet.

See [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) and
[../protocol/SECURITY.md](../protocol/SECURITY.md) §8.1.
