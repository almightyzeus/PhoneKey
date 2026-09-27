# PhoneKey

Use your Android phone as a **local, proximity-based, biometric authenticator**
for Linux: approve `sudo` and screen unlock with a fingerprint on your phone,
over Bluetooth Low Energy. There is no cloud, no internet, and no shared
password.

> ⚠️ **Status: pre-alpha, Phase 5 of 7.** Pairing, end-to-end authentication
> over BLE, and `sudo` through PAM (opt-in, password always still works). Not
> yet done: lock screen and login.
> PhoneKey is **not production-secure**. Always keep password authentication
> enabled.

## How it works

1. The laptop sends a fresh random challenge, which it signs itself, over BLE.
2. The phone shows what is being approved (for example, *sudo on chinuZeus*)
   and asks for your fingerprint through Android's `BiometricPrompt`.
3. The fingerprint unlocks **one use** of a private key held in Android
   Keystore hardware (StrongBox if available, otherwise TEE). The key signs the
   challenge.
4. The laptop verifies the signature against the public key it registered at
   pairing, and accepts each challenge only once.

The private key never leaves the phone, and no biometric data ever leaves the
phone. If the phone is absent or anything fails, you get the normal password
prompt.

## Documents

- [protocol/PROTOCOL.md](protocol/PROTOCOL.md): the wire protocol (platform-independent)
- [protocol/SECURITY.md](protocol/SECURITY.md): threat model, security decisions, **recovery procedures**
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Linux + Android design and phase plan
- [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md): development environment requirements
- [android/README.md](android/README.md), [linux/README.md](linux/README.md): build, test, and component notes

## MVP target

Android (Kotlin, minSdk 33) ↔ BLE ↔ Linux Mint 22 (Cinnamon, BlueZ, PAM):
`phonekey test`, then `sudo`, then screen unlock.

## Recovery

PhoneKey is only ever added as `auth sufficient` in front of the normal
password. To remove it without the phone, see
[SECURITY.md §9](protocol/SECURITY.md#9-recovery-procedures).

## License

Apache-2.0. See [LICENSE](LICENSE).
