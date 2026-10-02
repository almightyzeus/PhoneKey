# PhoneKey — Reliability test matrix (Phase 7)

The working document for [ROADMAP.md Phase 7](ROADMAP.md#phase-7--reliability--resilience).
It lists every condition, how to reproduce it, what must happen, what is
automated, and the recorded result on the test hardware:
**Linux Mint 22.3 laptop (Realtek RTL8822CU USB adapter) + Motorola Edge 50 Fusion.**

A result is recorded only after the test was actually run. "Not run" means
exactly that.

## The bar every condition must meet

From the roadmap's definition of *reliable*:

1. **Never worse than the password.** Each failure ends in the normal password
   prompt, at once when no phone is connected, otherwise within the PAM
   timeout (35 s sudo, 20 s unlock).
2. **Self-healing.** When the condition clears, PhoneKey works again with no
   reboot, no re-pairing and no manual Bluetooth steps.
3. **No stuck state.** No request outlives its TTL; nothing stays busy.
4. **Explainable.** `phonekey doctor` and the logs show what happened, with no secrets.

## How to run and record a test

1. Before: `phonekey doctor` should say "Looks fine." with the phone connected.
2. In a second terminal, watch the service:
   `journalctl -u phonekeyd -f -o short-precise | grep -E "connected via|subscribed|link error|disconnected|adapter|auth request|result"`
3. Cause the condition. Note the time it **clears** (for example, Bluetooth back on).
4. Note the time of the next `paired device … connected via …` line. The
   difference is the **reconnect time**.
5. Try `sudo -k && sudo true` during the condition (expect: password) and after it
   (expect: phone).
6. After: `phonekey doctor` again. It must not report controller timeouts after
   the test started, and the phone must be connected again.

Reconnect expectations follow the scan schedule (`scanning.py`): scanning starts
as soon as the phone is lost, in 12 s bursts every 30 s for 5 minutes, then
every 2 minutes. A sudo or unlock attempt triggers an immediate burst.
**Proposed target:** reconnect ≤ 60 s while the phone has been away less than
5 minutes. Confirm or revise it from the measurements below.

## Matrix

**Columns:** *Auto* = automated test(s); *Result* = manual result on the test
hardware, with date and reconnect time.

### Batch A — laptop side (quick, about 15 minutes)

| # | Condition | How to reproduce | Expected | Auto | Result |
|---|---|---|---|---|---|
| 5 | Bluetooth adapter restart | Unplug and replug the USB adapter (or `sudo systemctl restart bluetooth`) | Daemon follows the adapter (new `hciN` too) within a few seconds; link drops; reconnects. Other devices (mouse) reconnect too. | — | Not run |
| 6 | Laptop Bluetooth off/on | Bluetooth panel: off for 30 s, then on | While off: sudo → password at once. After on: scanning resumes by itself; reconnects. | — | Not run |
| 12 | `phonekeyd` restart | `sudo systemctl restart phonekeyd` (also try it while a phone prompt is open) | Open request fails → password; the phone prompt disappears (link drop); reconnects. | `test_resilience.DaemonRestartTest` | Not run |
| 13 | `phonekeyd` crash | `sudo systemctl kill -s KILL phonekeyd` | systemd restarts it after about 5 s; meanwhile sudo → password at once; reconnects. | — | Not run |
| 20 | Password fallback in every failure mode | During each test in this matrix | Always the normal password prompt, never an error or hang. | `test_pam` (absent daemon, wrong socket owner, timeout, deny, garbage) | Not run |

### Batch B — phone side (about 20 minutes)

| # | Condition | How to reproduce | Expected | Auto | Result |
|---|---|---|---|---|---|
| 2 | Phone sleep / wake | Screen off for 30+ minutes, then sudo | Link stays up (keepalive answered); prompt appears over the lock screen. | — | Not run |
| 7 | Android app/service restart | (a) app update via adb; (b) swipe app away from recents; (c) Settings → Force stop | (a) restarts by itself (verified once 2026-09-29); (b) service keeps running; (c) **Android does not restart a force-stopped app**: stays down until PhoneKey is opened (expected limitation; sudo → password). | — | Not run |
| 8 | Phone leaves range and returns | Walk away until disconnected (or put the phone in a metal tin), come back | Link drops → laptop bursts; reconnects when back. | — | Not run |
| 10 | Battery saver / background restrictions | Turn on Battery Saver; set PhoneKey battery usage to "Optimized" and to "Restricted"; leave for 1 hour | Foreground service survives Battery Saver and "Optimized". "Restricted" may stop it: record what happens and the required setting. | — | Not run |
| 11 | Phone Bluetooth off/on | Phone quick settings: Bluetooth off for 30 s, on | App shows "Bluetooth is off"; then advertises again; laptop reconnects. | — | Not run |

### Batch C — sleep and reboots (spread over a day)

| # | Condition | How to reproduce | Expected | Auto | Result |
|---|---|---|---|---|---|
| 1 | Laptop sleep / wake | Suspend for 5+ minutes, wake | Link drops on suspend; after wake the adapter returns and the phone reconnects; unlock works (screen locks on suspend). | — | Not run |
| 3 | Phone reboot | Reboot the phone, unlock once, do **not** open PhoneKey | Service starts after the first unlock (D‑14); laptop reconnects. | — | Not run |
| 4 | Linux reboot | Reboot the laptop | Service starts at boot; reconnects when the phone is reachable; sudo/unlock before that → password. | — | Not run |

### Batch D — background and long-running

| # | Condition | How to reproduce | Expected | Auto | Result |
|---|---|---|---|---|---|
| 9 | Phone temporarily unavailable | Stream Bluetooth audio from the phone, or use another heavy Bluetooth app, while using sudo | Either works, or a dead link is dropped by keepalive (≤ 26 s) and reconnects. | `test_core` keepalive tests | Not run |
| 14 | Stale connections | — (simulated) | Silent phone dropped after the hello/keepalive timeout; reconnect. | `test_core.test_silent_phone_after_subscribing_is_dropped`, `test_phone_that_stops_answering_keepalive_is_dropped` | Automated |
| 15 | Stale/incomplete fragmented messages | — (simulated) | Partial message dropped after 5 s; link keeps working. | `test_framing.test_stale_partial_message_is_dropped`, `test_late_continuation_after_timeout_is_rejected`; chaos test | Automated |
| 16 | Malformed packets | — (simulated) | Error reply or ignored; never a crash; link keeps working. | `test_codec_fuzz`, `test_core.test_malformed_frames_get_error_and_do_not_break_link`, `test_ipc.ParseRequestTest`, chaos test | Automated |
| 17 | Concurrent requests | Two terminals: `sudo -k; sudo true` at the same moment | One gets the phone, the other `BUSY` → password. | `test_core.test_duplicate_request_while_pending_is_busy`, Android `PromptGateTest` | Automated; manual not run |
| 18 | Timeout behaviour | Ignore the phone prompt | Password after 35 s (sudo) / 20 s (unlock); phone prompt withdrawn. | `test_core.test_timeout_fails_closed`, `test_caller_giving_up_withdraws_request`, `test_pam.test_silent_daemon_times_out` | Verified live 2026-09-29 (unlock) |
| 19 | Repeated attempts | Many sudo attempts in a row, mixing approve/deny/ignore | Every attempt ends; the phone's limit of 5 per minute applies; nothing stays busy. | `test_resilience.RepeatedAttemptsTest`, `PromptGateTest` | Automated; manual not run |
| 21 | No deadlocks | — | Every request ends exactly once. | `test_resilience.ChaosTest` (40 seeds × 250 random events; caught 5 of 5 injected core bugs) | Automated |
| 22 | No permanently stuck state | After each batch: `phonekey doctor` | Nothing pending, no pairing window, phone reconnected. | `test_resilience.ChaosTest` | Automated; manual not run |
| 23 | Recovery without reboot | Every test above | No test needs a reboot, re-pairing or manual Bluetooth commands (except the adapter replug in condition 25's failure mode). | — | Not run |
| 24 | Diagnostics without secrets | Review `phonekey doctor`, `journalctl -u phonekeyd`, `adb logcat -s PhoneKey` after the batches | Enough to explain each event; no keys, signatures, full messages. | `test_cli.DoctorTest` (doctor) | Not run |
| 25 | Coexistence with other Bluetooth devices | A full day of normal use with the Bluetooth mouse (and headphones) | Zero controller timeouts in `phonekey doctor` after the last adapter reset; mouse never needs a replug. | `test_scanning` (policy) | **In progress:** fix installed 2026-10-02 21:56; 0 timeouts after the adapter reset at 21:58 |

## Measurements

| Measure | Proposed target | Measured |
|---|---|---|
| Password prompt when no phone is connected | < 1 s | ≈15 ms (PAM harness, 2026-09-27) |
| Reconnect, phone away < 5 min | ≤ 60 s | — |
| Reconnect, phone away > 5 min | ≤ 2.5 min (or at once after a sudo attempt) | — |
| Soak without manual intervention | 7 days | — |

## Known limitations found so far

- **Force-stopped app stays stopped.** Android never restarts an app the user
  force-stopped, until it is opened again (condition 7c).
- **Reconnect is slower after long absences** because of burst scanning
  (condition 25 trade-off). A sudo or unlock attempt triggers an immediate scan.
