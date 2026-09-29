package dev.phonekey.authenticator.protocol

/**
 * Decides whether a valid AUTH_REQUEST may show a prompt (PROTOCOL.md §8.2 step 5,
 * SECURITY.md T-9): at most one prompt at a time, and at most [limit] prompts per
 * verifier per [windowMs]. Only admitted prompts count towards the limit.
 *
 * [clock] must be monotonic (SystemClock.elapsedRealtime on Android), so changing
 * the phone's time cannot reset the window.
 */
class PromptGate(
    private val clock: () -> Long,
    private val limit: Int = 5,
    private val windowMs: Long = 60_000L,
) {
    private val shown = mutableMapOf<String, ArrayDeque<Long>>()

    /** Null to admit (and count) the prompt, else the error to send instead. */
    fun admit(verifierKey: String, promptActive: Boolean): ErrorCode? {
        if (promptActive) return ErrorCode.BUSY
        val now = clock()
        val log = shown.getOrPut(verifierKey) { ArrayDeque() }
        while (log.isNotEmpty() && now - log.first() >= windowMs) log.removeFirst()
        if (log.size >= limit) return ErrorCode.RATE_LIMITED
        log.addLast(now)
        return null
    }
}
