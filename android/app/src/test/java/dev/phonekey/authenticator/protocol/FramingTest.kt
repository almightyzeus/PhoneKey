package dev.phonekey.authenticator.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

class FramingTest {
    private var now = 0L
    private val rx = Reassembler { now }

    private fun feedAll(frames: List<ByteArray>): ByteArray? {
        frames.dropLast(1).forEach { assertNull(rx.feed(it)) }
        return rx.feed(frames.last())
    }

    private fun assertMalformed(frame: ByteArray) {
        try {
            rx.feed(frame)
            fail("accepted")
        } catch (e: ProtocolException) {
            assertEquals(ErrorCode.MALFORMED, e.error)
        }
    }

    @Test
    fun roundtrip() {
        for (size in listOf(1, 17, 18, 1000, Codec.MAX_MESSAGE_SIZE)) {
            for (payload in listOf(17, 244, 509)) {
                if ((size + payload - 1) / payload > Framing.MAX_FRAGMENTS) continue
                val message = ByteArray(size) { (it % 251).toByte() }
                assertArrayEquals(message, feedAll(Framing.fragment(message, 5, payload)))
            }
        }
    }

    @Test
    fun matchesPythonFrameLayout() {
        // linux/daemon/phonekey/framing.py: fragment(b"abcde", 7, 2)
        val frames = Framing.fragment("abcde".toByteArray(), 7, 2)
        assertEquals(listOf("0700006162", "0701006364", "07020165"),
            frames.map { f -> f.joinToString("") { "%02x".format(it) } })
    }

    @Test
    fun outOfOrderAndRecovery() {
        val frames = Framing.fragment("hello world".toByteArray(), 3, 4)
        rx.feed(frames[0])
        assertMalformed(frames[2])
        assertArrayEquals("hello world".toByteArray(), feedAll(frames))
    }

    @Test
    fun mustStartAtZeroAndReservedFlags() {
        assertMalformed(Framing.fragment(ByteArray(50), 1, 10)[1])
        assertMalformed(byteArrayOf(0, 0, 3, 1))
        assertMalformed(byteArrayOf(0, 0, 1))
    }

    @Test
    fun stalePartialIsDropped() {
        rx.feed(Framing.fragment(ByteArray(20), 1, 4)[0])
        now += Framing.REASSEMBLY_TIMEOUT_MS + 1
        assertArrayEquals("new".toByteArray(), feedAll(Framing.fragment("new".toByteArray(), 2, 4)))
    }

    @Test
    fun maxPayload() {
        assertEquals(17, Framing.maxPayload(23))
        assertEquals(241, Framing.maxPayload(517)) // frames never exceed 244 bytes
        assertEquals(241, Framing.maxPayload(1000))
    }
}
