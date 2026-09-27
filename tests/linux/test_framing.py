"""BLE framing (PROTOCOL.md §6.2)."""

import unittest

from phonekey import framing
from phonekey.codec import MAX_MESSAGE_SIZE, ErrorCode, ProtocolError
from tests.helpers import FakeClock


class FramingTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.rx = framing.Reassembler(self.clock)

    def feed_all(self, frames):
        results = [self.rx.feed(f) for f in frames]
        self.assertTrue(all(r is None for r in results[:-1]))
        return results[-1]

    def test_roundtrip_various_sizes(self):
        for size in (1, 17, 18, 100, 1000, MAX_MESSAGE_SIZE):
            for payload in (1, 17, 244, 509):
                if -(-size // payload) > framing.MAX_FRAGMENTS:
                    continue
                with self.subTest(size=size, payload=payload):
                    message = bytes(i % 251 for i in range(size))
                    frames = framing.fragment(message, 7, payload)
                    self.assertTrue(all(len(f) <= payload + framing.HEADER_SIZE for f in frames))
                    self.assertEqual(message, self.feed_all(frames))

    def test_max_payload_from_mtu(self):
        self.assertEqual(17, framing.max_payload(23))
        self.assertEqual(241, framing.max_payload(517))  # frames never exceed 244 bytes
        self.assertEqual(241, framing.max_payload(1000))
        self.assertEqual(241, framing.max_payload(247))
        self.assertEqual(197, framing.max_payload(203))

    def test_too_many_fragments_refused_on_send(self):
        with self.assertRaises(ValueError):
            framing.fragment(bytes(256), 0, 1)

    def assert_malformed(self, frame):
        with self.assertRaises(ProtocolError) as ctx:
            self.rx.feed(frame)
        self.assertEqual(ErrorCode.MALFORMED, ctx.exception.code)

    def test_out_of_order_fragment(self):
        frames = framing.fragment(bytes(50), 1, 10)
        self.rx.feed(frames[0])
        self.assert_malformed(frames[2])

    def test_different_msg_no_before_last(self):
        a = framing.fragment(bytes(50), 1, 10)
        b = framing.fragment(bytes(50), 2, 10)
        self.rx.feed(a[0])
        self.assert_malformed(b[1])

    def test_must_start_at_fragment_zero(self):
        self.assert_malformed(framing.fragment(bytes(50), 1, 10)[1])

    def test_reserved_flags(self):
        self.assert_malformed(b"\x00\x00\x03x")

    def test_short_frame(self):
        self.assert_malformed(b"\x00\x00\x01")

    def test_oversized_message(self):
        frames = framing.fragment(bytes(MAX_MESSAGE_SIZE), 0, 200)
        extra = bytes([0, len(frames), 1]) + bytes(200)  # one fragment past the limit
        for f in frames[:-1]:
            self.rx.feed(f)
        self.assert_malformed(bytes([0, len(frames) - 1, 0]) + frames[-1][3:] + extra[3:])

    def test_error_discards_partial_and_recovers(self):
        frames = framing.fragment(b"hello world", 3, 4)
        self.rx.feed(frames[0])
        self.assert_malformed(frames[2])
        self.assertEqual(b"hello world", self.feed_all(frames))

    def test_stale_partial_message_is_dropped(self):
        frames = framing.fragment(b"first message", 1, 4)
        self.rx.feed(frames[0])
        self.clock.now += framing.REASSEMBLY_TIMEOUT + 0.1
        self.assertEqual(b"second", self.feed_all(framing.fragment(b"second", 2, 4)))

    def test_late_continuation_after_timeout_is_rejected(self):
        frames = framing.fragment(b"first message", 1, 4)
        self.rx.feed(frames[0])
        self.clock.now += framing.REASSEMBLY_TIMEOUT + 0.1
        self.assert_malformed(frames[1])

    def test_reset_on_disconnect(self):
        frames = framing.fragment(b"abcdefgh", 1, 4)
        self.rx.feed(frames[0])
        self.rx.reset()
        self.assertEqual(b"xyz", self.feed_all(framing.fragment(b"xyz", 9, 4)))


if __name__ == "__main__":
    unittest.main()
