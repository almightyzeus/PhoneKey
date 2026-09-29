package dev.phonekey.authenticator.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** SECURITY.md T-9: one prompt at a time, at most 5 per verifier per minute. */
class PromptGateTest {
    private var now = 1_000_000L
    private val gate = PromptGate({ now })

    @Test
    fun fivePromptsPerMinuteThenRateLimited() {
        repeat(5) { assertNull(gate.admit("laptop", promptActive = false)) }
        assertEquals(ErrorCode.RATE_LIMITED, gate.admit("laptop", promptActive = false))
    }

    @Test
    fun windowSlides() {
        repeat(5) { i -> now += i * 1_000L; assertNull(gate.admit("laptop", false)) }
        now += 59_000L - 10_000L // first prompt is now 59 s old
        assertEquals(ErrorCode.RATE_LIMITED, gate.admit("laptop", false))
        now += 1_000L // exactly 60 s after the first: it no longer counts
        assertNull(gate.admit("laptop", false))
        assertEquals(ErrorCode.RATE_LIMITED, gate.admit("laptop", false))
    }

    @Test
    fun busyWhileAPromptIsShowingAndDoesNotCount() {
        repeat(20) { assertEquals(ErrorCode.BUSY, gate.admit("laptop", promptActive = true)) }
        repeat(5) { assertNull(gate.admit("laptop", promptActive = false)) }
    }

    @Test
    fun busyWinsOverRateLimit() {
        repeat(5) { gate.admit("laptop", false) }
        assertEquals(ErrorCode.BUSY, gate.admit("laptop", promptActive = true))
    }

    @Test
    fun verifiersAreLimitedSeparately() {
        repeat(5) { gate.admit("laptop", false) }
        assertEquals(ErrorCode.RATE_LIMITED, gate.admit("laptop", false))
        assertNull(gate.admit("desktop", false))
    }

    @Test
    fun refusedRequestsDoNotExtendTheWindow() {
        repeat(5) { gate.admit("laptop", false) }
        repeat(100) { now += 500L; assertEquals(ErrorCode.RATE_LIMITED, gate.admit("laptop", false)) }
        now += 10_000L // 60 s after the first five
        assertNull(gate.admit("laptop", false))
    }
}
