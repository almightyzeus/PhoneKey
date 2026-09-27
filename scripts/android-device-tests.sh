#!/usr/bin/env bash
# Build, install and run the instrumented tests on a connected phone via `am instrument`.
#
# Used instead of `./gradlew connectedDebugAndroidTest`, which (AGP 9.4.1) reports
# failure even when every test passes. Select a device with ANDROID_SERIAL if
# several are connected.
set -euo pipefail

ANDROID_DIR="$(cd "$(dirname "$0")/../android" && pwd)"
ADB="${ADB:-${ANDROID_HOME:-$HOME/Android/Sdk}/platform-tools/adb}"

cd "$ANDROID_DIR"
./gradlew -q assembleDebug assembleDebugAndroidTest
"$ADB" install -r -t app/build/outputs/apk/debug/app-debug.apk >/dev/null
"$ADB" install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk >/dev/null

output="$("$ADB" shell am instrument -w dev.phonekey.authenticator.test/androidx.test.runner.AndroidJUnitRunner)"
echo "$output"
"$ADB" logcat -d -s PhoneKeyTest:I | grep -v '^---' | tail -n 20 || true
grep -q '^OK (' <<<"$output"
