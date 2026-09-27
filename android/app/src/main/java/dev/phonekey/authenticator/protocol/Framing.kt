package dev.phonekey.authenticator.protocol

/** BLE message framing (PROTOCOL.md §6.2); port of linux/daemon/phonekey/framing.py. */
object Framing {
    const val HEADER_SIZE = 3
    const val FLAG_LAST = 0x01
    const val MAX_FRAGMENTS = 255
    const val REASSEMBLY_TIMEOUT_MS = 5_000L
    const val DEFAULT_ATT_MTU = 23
    private const val ATT_HEADER = 3
    /**
     * One LE data PDU with Data Length Extension (251) minus L2CAP (4) and ATT (3) headers.
     * Larger frames span several link-layer PDUs, which some controllers do not sustain.
     */
    const val MAX_FRAME = 244

    fun maxPayload(attMtu: Int): Int = maxOf(1, minOf(attMtu - ATT_HEADER, MAX_FRAME) - HEADER_SIZE)

    fun fragment(message: ByteArray, msgNo: Int, payloadSize: Int): List<ByteArray> {
        require(message.isNotEmpty()) { "empty message" }
        val chunks = (message.indices step payloadSize).map {
            message.copyOfRange(it, minOf(it + payloadSize, message.size))
        }
        require(chunks.size <= MAX_FRAGMENTS) { "message needs ${chunks.size} fragments" }
        return chunks.mapIndexed { i, chunk ->
            byteArrayOf(msgNo.toByte(), i.toByte(), if (i == chunks.lastIndex) FLAG_LAST.toByte() else 0) + chunk
        }
    }
}

/** Collects frames from one peer. Any rule violation discards the partial message. */
class Reassembler(private val clock: () -> Long = System::currentTimeMillis) {
    private var msgNo = -1
    private var nextFrag = 0
    private var started = 0L
    private val buffer = java.io.ByteArrayOutputStream()

    fun reset() {
        msgNo = -1
        nextFrag = 0
        buffer.reset()
    }

    private fun fail(detail: String): ProtocolException {
        reset()
        return ProtocolException(ErrorCode.MALFORMED, detail)
    }

    /** Returns the complete message when the LAST frame arrives, else null. */
    fun feed(frame: ByteArray): ByteArray? {
        if (frame.size < Framing.HEADER_SIZE + 1) throw fail("frame too short")
        val no = frame[0].toInt() and 0xFF
        val frag = frame[1].toInt() and 0xFF
        val flags = frame[2].toInt() and 0xFF
        if (flags and Framing.FLAG_LAST.inv() != 0) throw fail("reserved frame flags set")
        if (msgNo >= 0 && clock() - started > Framing.REASSEMBLY_TIMEOUT_MS) reset() // stale partial message
        if (msgNo < 0) {
            if (frag != 0) throw fail("message does not start at fragment 0")
            msgNo = no
            started = clock()
        } else if (no != msgNo || frag != nextFrag) {
            throw fail("frame out of order")
        }
        if (buffer.size() + frame.size - Framing.HEADER_SIZE > Codec.MAX_MESSAGE_SIZE) throw fail("message too large")
        buffer.write(frame, Framing.HEADER_SIZE, frame.size - Framing.HEADER_SIZE)
        nextFrag = frag + 1
        if (flags and Framing.FLAG_LAST != 0) {
            val message = buffer.toByteArray()
            reset()
            return message
        }
        if (nextFrag >= Framing.MAX_FRAGMENTS) throw fail("too many fragments")
        return null
    }
}
