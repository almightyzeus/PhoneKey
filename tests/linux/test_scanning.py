"""Scan policy (scanning.py): scan only while needed, so other Bluetooth devices keep working."""

import unittest

from phonekey.scanning import BURST, LONG_PAUSE, OFF, PAIRING, RECENT_PAUSE, RECENT_WINDOW, SCAN, ScanPolicy


def run(policy, start, end, missing=1, pairing=False, step=1.0):
    """Seconds spent scanning between start and end, deciding every `step` seconds."""
    scanning, t = 0.0, start
    while t < end:
        if policy.decide(t, pairing, missing) == SCAN:
            scanning += step
        t += step
    return scanning


class ScanPolicyTest(unittest.TestCase):
    def test_no_scanning_when_all_phones_connected_or_none_paired(self):
        policy = ScanPolicy()
        self.assertEqual(0, run(policy, 0, 3600, missing=0))

    def test_pairing_window_scans_continuously(self):
        self.assertEqual(PAIRING, ScanPolicy().decide(0, True, 0))
        self.assertEqual(PAIRING, ScanPolicy().decide(0, True, 3))

    def test_missing_phone_is_looked_for_at_once(self):
        policy = ScanPolicy()
        policy.decide(0, False, 0)
        self.assertEqual(SCAN, policy.decide(10, False, 1))

    def test_bursts_then_pauses(self):
        policy = ScanPolicy()
        self.assertEqual(SCAN, policy.decide(0, False, 1))
        self.assertEqual(SCAN, policy.decide(BURST - 1, False, 1))
        self.assertEqual(OFF, policy.decide(BURST, False, 1))
        self.assertEqual(OFF, policy.decide(BURST + RECENT_PAUSE - 1, False, 1))
        self.assertEqual(SCAN, policy.decide(BURST + RECENT_PAUSE, False, 1))

    def test_duty_cycle_is_low_and_drops_further_after_a_while(self):
        policy = ScanPolicy()
        first = run(policy, 0, RECENT_WINDOW)
        later = run(policy, RECENT_WINDOW + 600, RECENT_WINDOW + 4200)  # one hour, long pauses
        self.assertLess(first / RECENT_WINDOW, 0.35)
        self.assertLess(later / 3600, BURST / (BURST + LONG_PAUSE) + 0.02)
        self.assertGreater(later, 0)  # still looking, so the phone is found eventually

    def test_wake_scans_now_even_during_a_long_pause(self):
        policy = ScanPolicy()
        run(policy, 0, RECENT_WINDOW + 100)  # now in long pauses
        t = RECENT_WINDOW + 101
        while policy.decide(t, False, 1) == SCAN:  # wait until a pause
            t += 1
        policy.wake(t)
        self.assertEqual(SCAN, policy.decide(t, False, 1))

    def test_reconnect_resets_the_schedule(self):
        policy = ScanPolicy()
        run(policy, 0, 2000)
        policy.decide(2000, False, 0)  # phone back
        self.assertEqual(SCAN, policy.decide(2100, False, 1))  # lost again: look at once
        self.assertEqual(OFF, policy.decide(2100 + BURST, False, 1))
        self.assertEqual(SCAN, policy.decide(2100 + BURST + RECENT_PAUSE, False, 1))  # short pauses again


if __name__ == "__main__":
    unittest.main()
