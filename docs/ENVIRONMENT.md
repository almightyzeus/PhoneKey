# Development environment (as inspected 2026-09-27)

These are the findings from the Phase 0 inspection. They are read-only
observations; nothing was installed or changed.

## Linux laptop

| Item | Found |
|---|---|
| OS | Linux Mint 22.3 "Zena" (Ubuntu 24.04 base), x86_64 |
| Desktop | Cinnamon on **X11** |
| Display manager | LightDM |
| Kernel | 6.8.0 |
| Bluetooth | BlueZ 5.72, `bluetooth.service` active, not rfkill-blocked |
| Adapter | hci0, Realtek via btusb (USB 13d3:3548). Roles: **central, peripheral** |
| BlueZ D-Bus | `Adapter1`, `GattManager1`, `LEAdvertisingManager1` (4 instances; includes tx-power, appearance, local-name) |
| BlueZ D-Bus policy | `root`, group `bluetooth` (exists, gid 109), and default context may talk to `org.bluez` |
| sudo | 1.9.15p5 (C sudo, not sudo-rs) |
| Python | 3.12.3 with `cryptography` 41.0.7, `dbus` (python3-dbus), `gi` 3.48, `nacl` 1.5 |
| Toolchain | gcc 13.3, make 4.3, pkg-config, `libssl-dev`, git 2.43, Java 21 |
| **Missing** | `libpam0g-dev` (needed in Phase 5), cmake/meson (not needed) |

### PAM

- `/etc/pam.d/common-auth`: `pam_unix nullok` → `pam_deny` → `pam_permit`,
  plus `pam_ecryptfs unwrap` and `pam_cap`. `/home` is **not** ecryptfs, so
  pam_ecryptfs does nothing.
- `/etc/pam.d/sudo`: `@include common-auth` (plus session modules).
- `/etc/pam.d/cinnamon-screensaver`: `@include common-auth`, then
  `pam_gnome_keyring` (optional).
- `/etc/pam.d/lightdm`: `pam_nologin`, `nopasswdlogin` group check,
  `@include common-auth`, gnome-keyring/kwallet (optional).

Consequence: PhoneKey can be enabled **per service** by inserting one line
before `@include common-auth`, without touching the shared file.

## Android

| Item | Found |
|---|---|
| Android toolchain | Android Studio 2026.1.4, SDK in `~/Android/Sdk` (platform 37, build-tools 36.0.0, platform-tools). Gradle 9.8.0 (wrapper), AGP 9.4.1, JDK 21. Gradle needs `-Djava.net.preferIPv4Stack=true` on this network (broken IPv6). |
| Test device | Motorola **Edge 50 Fusion** (`cuscoi`, Snapdragon `parrot`), Android 16 / API 36, patch 2026-07-01, verified boot green |
| Keystore | KeyMint v3 (`hardware_keystore=300`), **no StrongBox**. Keys are TEE-backed. Attestation works (5-cert chain). |
| Biometrics | Fingerprint: Class 3 (usable). Face unlock present, but not offered by `BIOMETRIC_STRONG`. |
| adb | Wireless debugging (`adb pair` + `adb connect`). USB did not enumerate with the cable tried. The connection drops when the phone sleeps. |

## Required before each phase (user action; nothing is installed automatically)

| Phase | Needs |
|---|---|
| 1 | Android Studio (bundles the SDK, Gradle, and a JDK), the platform SDK for the chosen `compileSdk`, `adb` (platform-tools), USB debugging enabled on the phone, and at least one fingerprint enrolled |
| 2 | Nothing new (system Python packages) |
| 3 | Creating the `phonekey` system user and systemd unit via `scripts/install.sh` (shown and confirmed first) |
| 5 | `sudo apt install libpam0g-dev` |
