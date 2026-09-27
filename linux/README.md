# PhoneKey — Linux verifier

**Current state: Phase 2.** This is a verifier library and CLI with no daemon,
no BLE, and no PAM. It doesn't change the system: it writes only to a
user-local development directory, and `phonekey test --simulate` uses a
throwaway temporary one. It depends only on Python 3 and the Debian packages
`python3-cryptography` and (optionally, for `status`) `python3-dbus`.

## Layout

```
linux/daemon/phonekey/      Python package (becomes phonekeyd in Phase 3)
  codec.py                  strict TLV encoding (PROTOCOL.md §3–4)
  crypto.py                 ECDSA P-256 / SHA-256, labels, key loading
  registry.py               paired-device records (one JSON file per device)
  verifier.py               challenges, single-use pending table, pairing
  simulator.py              software authenticator: tests + `--simulate` only
  cli.py                    `phonekey` command
linux/cli/phonekey          development launcher for the CLI
linux/pam/                  (Phase 5)
```

## CLI

```bash
linux/cli/phonekey status            # Bluetooth adapter, paired devices
linux/cli/phonekey devices           # list paired devices
linux/cli/phonekey unpair <prefix>   # revoke one device (works without the phone)
linux/cli/phonekey unpair --all
linux/cli/phonekey test --simulate   # full pairing + auth + attack checks, in memory
```

The registry defaults to `~/.local/state/phonekey-dev/`, or
`$PHONEKEY_STATE_DIR` if set. The system daemon will use `/var/lib/phonekey`
(Phase 3). `pair`, `enable`, `disable` and `logs` arrive with the phases that
need them. `phonekey test` without `--simulate` needs the BLE transport (Phase 3).

Example:

```
$ linux/cli/phonekey test --simulate
PhoneKey — simulated authenticator (no Bluetooth, temporary registry)
--------
Bluetooth: available (hci0) (not used)
Paired device: Simulated phone [1cb9 c35a 71c4 9aaf]
Connection: simulated
Authentication: ready

Authentication request sent...
Waiting for biometric... (simulated approval)
✓ Signature verified
✓ PhoneKey authentication successful

Security checks:
✓ replayed response rejected (UNKNOWN_REQUEST)
✓ tampered signature rejected (BAD_SIGNATURE)
✓ modified request rejected (BAD_SIGNATURE)
✓ unknown phone rejected (UNKNOWN_DEVICE)
✓ user denial rejected (USER_DENIED)
```

## Tests

```bash
scripts/linux-tests.sh          # 84 tests, ~2 s, stdlib unittest
```

| Area | File |
|---|---|
| Codec rules and shared vectors (`protocol/test-vectors/v1.json`) | `tests/linux/test_codec.py` |
| Fuzzing: malformed input never crashes or authenticates | `tests/protocol/test_codec_fuzz.py` |
| Authentication: replay, tampering, unknown phone, revocation, expiry, busy, labels, versions | `tests/linux/test_verifier.py` |
| Pairing: proof of possession, nonce/hash binding, window, software keys, attestation informational | `tests/linux/test_pairing.py` |
| Registry: persistence, 0700/0600 permissions, tamper detection, prefixes | `tests/linux/test_registry.py` |
| CLI, including "simulation never touches the real registry" | `tests/linux/test_cli.py` |

The security checks were **mutation-tested**. Each check in the verifier,
codec, registry and crypto (15 in total) was disabled one at a time, and the
suite had to fail. It fails for every one.

`scripts/gen-test-vectors.py` regenerates the vectors. Keys are ephemeral, and
only public keys and signatures are written. The Android implementation must
pass the same vectors when its codec is written (Phase 3).

## Security notes

- The software simulator is refused by a normal `Verifier`, because its
  `key_security` is SOFTWARE. The CLI only ever pairs it into a temporary
  registry, so a software key can never become a PAM credential.
- Records are re-read on every lookup, so unpairing takes effect at once.
  A record whose `device_id` doesn't match its public key is ignored with a
  warning.
- Pending challenges live only in memory: single use, 30 s, one per device.
