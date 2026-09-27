package dev.phonekey.authenticator.protocol

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * PhoneKey v1 message encoding (protocol/PROTOCOL.md §3–§4). A line-by-line port of
 * linux/daemon/phonekey/codec.py; both must pass protocol/test-vectors/v1.json.
 */
enum class MsgType(val code: Int) {
    PAIR_REQUEST(0x01), PAIR_RESPONSE(0x02), AUTH_REQUEST(0x03),
    AUTH_RESPONSE(0x04), STATUS(0x05), ERROR(0x06);

    companion object {
        fun of(code: Int): MsgType? = entries.firstOrNull { it.code == code }
    }
}

enum class ErrorCode(val code: Int) {
    MALFORMED(0x0001), UNSUPPORTED_VERSION(0x0002), UNKNOWN_VERIFIER(0x0003), UNKNOWN_DEVICE(0x0004),
    BAD_SIGNATURE(0x0005), EXPIRED(0x0006), UNKNOWN_REQUEST(0x0007), BUSY(0x0008), USER_DENIED(0x0009),
    BIOMETRIC_FAILED(0x000A), KEY_INVALIDATED(0x000B), NOT_PAIRING(0x000C), RATE_LIMITED(0x000D),
    INTERNAL(0x000E), INSECURE_KEY(0x000F);

    companion object {
        fun of(code: Int): ErrorCode? = entries.firstOrNull { it.code == code }
    }
}

object StatusCode {
    const val READY = 1L
    const val PROMPTING = 2L
    const val PAIRED = 3L
    const val BUSY = 4L
}

class ProtocolException(val error: ErrorCode, val detail: String) : Exception("${error.name}: $detail")

enum class Kind(val width: Int) { BYTES(0), STRING(0), U8(1), U16(2), U32(4), U64(8) }

data class FieldSpec(val tag: Int, val name: String, val kind: Kind, val min: Int = 0, val max: Int = 0)

/** Decoded message. Integer fields are Long, bytes are ByteArray, strings are String. */
class Message(
    val type: MsgType,
    val fields: Map<String, Any>,
    val raw: ByteArray,
    /** Bytes covered by the signature (everything before the signature TLV), or null. */
    val signedPart: ByteArray?,
) {
    fun has(name: String) = name in fields
    fun bytes(name: String) = fields.getValue(name) as ByteArray
    fun string(name: String) = fields.getValue(name) as String
    fun long(name: String) = fields.getValue(name) as Long
}

object Codec {
    val MAGIC = byteArrayOf(0x50, 0x4B)
    const val VERSION = 1
    const val MAX_MESSAGE_SIZE = 16384
    const val HEADER_SIZE = 4
    const val SIGNATURE_TAG = 0x7F

    val FIELDS = listOf(
        FieldSpec(0x01, "verifier_id", Kind.BYTES, 32, 32),
        FieldSpec(0x02, "device_id", Kind.BYTES, 32, 32),
        FieldSpec(0x03, "request_id", Kind.BYTES, 16, 16),
        FieldSpec(0x04, "challenge", Kind.BYTES, 32, 32),
        FieldSpec(0x05, "action", Kind.STRING, 1, 64),
        FieldSpec(0x06, "resource", Kind.STRING, 1, 256),
        FieldSpec(0x07, "account", Kind.STRING, 1, 64),
        FieldSpec(0x08, "issued_at", Kind.U64),
        FieldSpec(0x09, "ttl_ms", Kind.U32),
        FieldSpec(0x0A, "public_key", Kind.BYTES, 91, 91),
        FieldSpec(0x0B, "display_name", Kind.STRING, 1, 64),
        FieldSpec(0x0C, "pairing_nonce", Kind.BYTES, 32, 32),
        FieldSpec(0x0D, "request_hash", Kind.BYTES, 32, 32),
        FieldSpec(0x0E, "key_security", Kind.U8),
        FieldSpec(0x0F, "attestation_chain", Kind.BYTES, 0, 12288),
        FieldSpec(0x10, "status", Kind.U8),
        FieldSpec(0x11, "error_code", Kind.U16),
        FieldSpec(0x12, "error_detail", Kind.STRING, 0, 128),
        FieldSpec(SIGNATURE_TAG, "signature", Kind.BYTES, 8, 72),
    )
    private val byTag = FIELDS.associateBy { it.tag }
    val byName = FIELDS.associateBy { it.name }

    private fun schema(required: String, optional: String = "") =
        required.split(" ").toSet() to optional.split(" ").filter { it.isNotEmpty() }.toSet()

    private val schemas = mapOf(
        MsgType.PAIR_REQUEST to schema(
            "verifier_id action account issued_at ttl_ms public_key display_name pairing_nonce signature"
        ),
        MsgType.PAIR_RESPONSE to schema(
            "verifier_id device_id public_key display_name pairing_nonce request_hash key_security signature",
            "attestation_chain",
        ),
        MsgType.AUTH_REQUEST to schema(
            "verifier_id device_id request_id challenge action resource account issued_at ttl_ms signature"
        ),
        MsgType.AUTH_RESPONSE to schema("verifier_id device_id request_id request_hash signature"),
        MsgType.STATUS to schema("status", "verifier_id device_id request_id"),
        MsgType.ERROR to schema("error_code", "request_id error_detail"),
    )

    private val forbiddenChars: Set<Int> = buildSet {
        addAll(0x00 until 0x20); addAll(0x7F until 0xA0)
        add(0x061C); add(0x200E); add(0x200F)
        addAll(0x202A..0x202E); addAll(0x2066..0x2069)
    }

    private fun malformed(detail: String) = ProtocolException(ErrorCode.MALFORMED, detail)

    private fun parseValue(spec: FieldSpec, raw: ByteArray): Any {
        if (spec.kind.width > 0) {
            if (raw.size != spec.kind.width) throw malformed("${spec.name}: expected ${spec.kind.width} bytes")
            return raw.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
        }
        if (raw.size !in spec.min..spec.max) throw malformed("${spec.name}: length ${raw.size} out of range")
        if (spec.kind == Kind.BYTES) return raw
        val text = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
        } catch (e: CharacterCodingException) {
            throw malformed("${spec.name}: invalid UTF-8")
        }
        text.codePoints().forEach {
            if (it in forbiddenChars) throw malformed("${spec.name}: forbidden character U+%04X".format(it))
        }
        return text
    }

    private fun encodeValue(spec: FieldSpec, value: Any): ByteArray {
        val raw = when (spec.kind) {
            Kind.U8, Kind.U16, Kind.U32, Kind.U64 -> {
                val v = (value as? Number)?.toLong() ?: throw IllegalArgumentException("${spec.name}: expected integer")
                if (spec.kind != Kind.U64 && (v < 0 || v >= (1L shl (8 * spec.kind.width)))) {
                    throw malformed("${spec.name}: $v out of range")
                }
                ByteArray(spec.kind.width) { i -> (v ushr (8 * (spec.kind.width - 1 - i))).toByte() }
            }
            Kind.STRING -> (value as? String ?: throw IllegalArgumentException("${spec.name}: expected String"))
                .toByteArray(StandardCharsets.UTF_8)
            Kind.BYTES -> value as? ByteArray ?: throw IllegalArgumentException("${spec.name}: expected ByteArray")
        }
        parseValue(spec, raw) // same checks as decoding
        return raw
    }

    private fun encode(type: MsgType, fields: Map<String, Any>, unsigned: Boolean): ByteArray {
        var (required, optional) = schemas.getValue(type)
        if (unsigned) {
            require("signature" in required) { "${type.name} is not a signed message type" }
            require("signature" !in fields) { "unsigned encoding must not contain a signature" }
            required = required - "signature"
        }
        val unknown = fields.keys - required - optional
        if (unknown.isNotEmpty()) throw malformed("fields not allowed in ${type.name}: $unknown")
        val missing = required - fields.keys
        if (missing.isNotEmpty()) throw malformed("missing fields in ${type.name}: $missing")

        val out = java.io.ByteArrayOutputStream()
        out.write(MAGIC)
        out.write(VERSION)
        out.write(type.code)
        for (spec in fields.keys.map { byName.getValue(it) }.sortedBy { it.tag }) {
            val value = encodeValue(spec, fields.getValue(spec.name))
            out.write(spec.tag)
            out.write(value.size ushr 8)
            out.write(value.size and 0xFF)
            out.write(value)
        }
        if (out.size() > MAX_MESSAGE_SIZE) throw malformed("message too large")
        return out.toByteArray()
    }

    /** Encodes a complete message (including `signature` for signed types). */
    fun encode(type: MsgType, fields: Map<String, Any>): ByteArray = encode(type, fields, unsigned = false)

    /** Encodes a signed message type without its signature: the bytes to sign (after the label). */
    fun encodeUnsigned(type: MsgType, fields: Map<String, Any>): ByteArray = encode(type, fields, unsigned = true)

    /** Appends the signature TLV to the output of [encodeUnsigned] and validates the result. */
    fun withSignature(unsigned: ByteArray, signature: ByteArray): ByteArray {
        val spec = byName.getValue("signature")
        val value = encodeValue(spec, signature)
        val data = unsigned + byteArrayOf(SIGNATURE_TAG.toByte(), (value.size ushr 8).toByte(), value.size.toByte()) + value
        decode(data)
        return data
    }

    /** Parses and validates a message. Throws [ProtocolException] on any violation. */
    fun decode(data: ByteArray): Message {
        if (data.size > MAX_MESSAGE_SIZE) throw malformed("message too large")
        if (data.size < HEADER_SIZE || data[0] != MAGIC[0] || data[1] != MAGIC[1]) throw malformed("bad header")
        if (data[2].toInt() != VERSION) throw ProtocolException(ErrorCode.UNSUPPORTED_VERSION, "version ${data[2]}")
        val type = MsgType.of(data[3].toInt() and 0xFF) ?: throw malformed("unknown message type")

        val (required, optional) = schemas.getValue(type)
        val allowed = required + optional
        val fields = LinkedHashMap<String, Any>()
        var pos = HEADER_SIZE
        var lastTag = 0
        var signedEnd = -1
        while (pos < data.size) {
            if (data.size - pos < 3) throw malformed("truncated field header")
            val tag = data[pos].toInt() and 0xFF
            val length = ((data[pos + 1].toInt() and 0xFF) shl 8) or (data[pos + 2].toInt() and 0xFF)
            val start = pos + 3
            val end = start + length
            if (end > data.size) throw malformed("field overruns message")
            if (tag <= lastTag) throw malformed("field out of order or repeated")
            val spec = byTag[tag]
            if (spec == null || spec.name !in allowed) throw malformed("field 0x%02x not allowed".format(tag))
            fields[spec.name] = parseValue(spec, data.copyOfRange(start, end))
            if (tag == SIGNATURE_TAG) signedEnd = pos
            lastTag = tag
            pos = end
        }
        val missing = required - fields.keys
        if (missing.isNotEmpty()) throw malformed("missing fields in ${type.name}: $missing")
        return Message(type, fields, data, if (signedEnd >= 0) data.copyOfRange(0, signedEnd) else null)
    }
}
