package dev.phonekey.authenticator.protocol

import dev.phonekey.authenticator.crypto.SignatureVerifier
import java.security.MessageDigest

/** Signature domain-separation labels (PROTOCOL.md §2). */
object Labels {
    val PAIR_REQUEST = "PhoneKey/v1/pair-request\u0000".toByteArray(Charsets.US_ASCII)
    val PAIR_RESPONSE = "PhoneKey/v1/pair-response\u0000".toByteArray(Charsets.US_ASCII)
    val AUTH_REQUEST = "PhoneKey/v1/auth-request\u0000".toByteArray(Charsets.US_ASCII)
    val AUTH_ASSERTION = "PhoneKey/v1/auth-assertion\u0000".toByteArray(Charsets.US_ASCII)
}

/** A laptop (verifier) this phone is paired with. */
data class VerifierRecord(
    val verifierId: ByteArray,
    val publicKey: ByteArray,
    val displayName: String,
    val account: String,
    val keyAlias: String,
    val deviceId: ByteArray,
    /** Bluetooth address of the laptop: metadata for reconnecting, never identity. */
    val address: String?,
)

/** A validated PAIR_REQUEST, waiting for the user's decision. */
class PairOffer(
    val request: ByteArray,
    val requestHash: ByteArray,
    val verifierId: ByteArray,
    val verifierKey: ByteArray,
    val displayName: String,
    val account: String,
    val nonce: ByteArray,
)

sealed interface AuthDecision {
    /** Valid request from a paired verifier: show it and ask for a biometric. */
    class Prompt(
        val record: VerifierRecord,
        val requestId: ByteArray,
        val action: String,
        val resource: String,
        val account: String,
        val ttlMs: Long,
        /** AUTH_RESPONSE without signature; sign LABEL_AUTH_ASSERTION + this. */
        val unsignedResponse: ByteArray,
    ) : AuthDecision

    /** Refuse without prompting; send this ERROR back. */
    class Reply(val message: ByteArray) : AuthDecision

    /** Not addressed to this phone's key: stay silent. */
    data object Ignore : AuthDecision
}

/**
 * Authenticator side of the protocol (PROTOCOL.md §5.2, §8.2), independent of
 * Keystore and BLE. Mirrors linux/daemon/phonekey/simulator.py.
 */
object AuthenticatorCore {
    const val PAIR_ACTION = "phonekey.pair"
    private const val MAX_ATTESTATION = 12288

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun keyAlias(verifierId: ByteArray): String =
        "phonekey.v1." + verifierId.copyOf(8).joinToString("") { "%02x".format(it) }

    /** Validates a PAIR_REQUEST, including the verifier's proof of possession. */
    fun parsePairRequest(data: ByteArray): PairOffer {
        val msg = Codec.decode(data)
        if (msg.type != MsgType.PAIR_REQUEST) throw ProtocolException(ErrorCode.MALFORMED, "expected PAIR_REQUEST")
        if (msg.string("action") != PAIR_ACTION) throw ProtocolException(ErrorCode.MALFORMED, "bad pairing action")
        val spki = msg.bytes("public_key")
        val key = try {
            SignatureVerifier.publicKeyFromSpki(spki)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException(ErrorCode.MALFORMED, "bad verifier key")
        }
        if (!msg.bytes("verifier_id").contentEquals(sha256(spki))) {
            throw ProtocolException(ErrorCode.MALFORMED, "verifier_id does not match key")
        }
        if (!SignatureVerifier.verify(key, Labels.PAIR_REQUEST + msg.signedPart!!, msg.bytes("signature"))) {
            throw ProtocolException(ErrorCode.BAD_SIGNATURE, "bad verifier signature")
        }
        return PairOffer(data, sha256(data), msg.bytes("verifier_id"), spki, msg.string("display_name"),
            msg.string("account"), msg.bytes("pairing_nonce"))
    }

    fun unsignedPairResponse(
        offer: PairOffer,
        deviceSpki: ByteArray,
        phoneName: String,
        keySecurity: Int,
        attestationChain: List<ByteArray>?,
    ): ByteArray {
        val fields = mutableMapOf<String, Any>(
            "verifier_id" to offer.verifierId,
            "device_id" to sha256(deviceSpki),
            "public_key" to deviceSpki,
            "display_name" to sanitizeName(phoneName),
            "pairing_nonce" to offer.nonce,
            "request_hash" to offer.requestHash,
            "key_security" to keySecurity,
        )
        encodeAttestation(attestationChain)?.let { fields["attestation_chain"] = it }
        return Codec.encodeUnsigned(MsgType.PAIR_RESPONSE, fields)
    }

    /** u16-length-prefixed DER certificates; null (omitted, informational) if absent or too large. */
    fun encodeAttestation(chain: List<ByteArray>?): ByteArray? {
        if (chain.isNullOrEmpty()) return null
        val out = java.io.ByteArrayOutputStream()
        for (cert in chain) {
            if (cert.size > 0xFFFF) return null
            out.write(cert.size ushr 8)
            out.write(cert.size and 0xFF)
            out.write(cert)
        }
        return if (out.size() <= MAX_ATTESTATION) out.toByteArray() else null
    }

    fun evaluateAuthRequest(data: ByteArray, lookup: (ByteArray) -> VerifierRecord?): AuthDecision {
        val msg = try {
            Codec.decode(data)
        } catch (e: ProtocolException) {
            return AuthDecision.Reply(error(e.error))
        }
        if (msg.type != MsgType.AUTH_REQUEST) return AuthDecision.Reply(error(ErrorCode.MALFORMED))
        val requestId = msg.bytes("request_id")
        val record = lookup(msg.bytes("verifier_id"))
            ?: return AuthDecision.Reply(error(ErrorCode.UNKNOWN_VERIFIER, requestId))
        val key = SignatureVerifier.publicKeyFromSpki(record.publicKey)
        if (!SignatureVerifier.verify(key, Labels.AUTH_REQUEST + msg.signedPart!!, msg.bytes("signature"))) {
            return AuthDecision.Reply(error(ErrorCode.BAD_SIGNATURE, requestId))
        }
        if (!msg.bytes("device_id").contentEquals(record.deviceId)) return AuthDecision.Ignore
        if (msg.string("account") != record.account) {
            return AuthDecision.Reply(error(ErrorCode.UNKNOWN_DEVICE, requestId))
        }
        val unsigned = Codec.encodeUnsigned(MsgType.AUTH_RESPONSE, mapOf(
            "verifier_id" to record.verifierId,
            "device_id" to record.deviceId,
            "request_id" to requestId,
            "request_hash" to sha256(data),
        ))
        return AuthDecision.Prompt(record, requestId, msg.string("action"), msg.string("resource"),
            msg.string("account"), msg.long("ttl_ms"), unsigned)
    }

    fun error(code: ErrorCode, requestId: ByteArray? = null): ByteArray {
        val fields = mutableMapOf<String, Any>("error_code" to code.code)
        if (requestId != null) fields["request_id"] = requestId
        return Codec.encode(MsgType.ERROR, fields)
    }

    fun status(code: Long, record: VerifierRecord? = null): ByteArray {
        val fields = mutableMapOf<String, Any>("status" to code)
        if (record != null) {
            fields["verifier_id"] = record.verifierId
            fields["device_id"] = record.deviceId
        }
        return Codec.encode(MsgType.STATUS, fields)
    }

    /** A display name the codec accepts: no control/bidi characters, 1–64 UTF-8 bytes. */
    fun sanitizeName(name: String): String {
        val cleaned = name.filter { it >= ' ' && it !in '\u007f'..'\u009f' && it !in "؜‎‏" &&
            it !in '‪'..'‮' && it !in '⁦'..'⁩' }.trim()
        var result = cleaned.ifEmpty { "Android phone" }
        while (result.toByteArray(Charsets.UTF_8).size > 64) result = result.dropLast(1)
        return result
    }

    /** Human-readable text for the prompt. Unknown actions are shown verbatim. */
    fun describeAction(action: String): String = when (action) {
        "linux.sudo" -> "sudo authentication"
        "linux.unlock" -> "Unlock screen"
        "linux.login" -> "Log in"
        "phonekey.test" -> "PhoneKey test"
        else -> action
    }
}
