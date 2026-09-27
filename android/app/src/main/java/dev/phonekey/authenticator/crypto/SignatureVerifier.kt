package dev.phonekey.authenticator.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

/**
 * ECDSA P-256 / SHA-256 verification using only standard JCA APIs, so it runs the
 * same on Android and in plain JVM unit tests. Mirrors what the Linux verifier does.
 */
object SignatureVerifier {
    const val ALGORITHM = "SHA256withECDSA"

    /** Order n of the NIST P-256 group (FIPS 186-4, D.1.2.3). */
    private val P256_ORDER = BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
    )

    /** Parses a DER SubjectPublicKeyInfo and requires it to be a P-256 key. */
    fun publicKeyFromSpki(spki: ByteArray): ECPublicKey {
        val key = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        } catch (e: InvalidKeySpecException) {
            throw IllegalArgumentException("Not a valid EC SubjectPublicKeyInfo", e)
        }
        require(key is ECPublicKey && key.params.order == P256_ORDER) { "Not a P-256 public key" }
        return key
    }

    /** True only if [signature] is a valid DER ECDSA signature of [message] by [publicKey]. */
    fun verify(publicKey: ECPublicKey, message: ByteArray, signature: ByteArray): Boolean =
        try {
            Signature.getInstance(ALGORITHM).run {
                initVerify(publicKey)
                update(message)
                verify(signature)
            }
        } catch (e: SignatureException) {
            false // malformed signature encoding
        }

    /** device_id / verifier_id: SHA-256 of the DER SubjectPublicKeyInfo (PROTOCOL.md §1). */
    fun keyId(spki: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(spki)
}

object Challenges {
    const val SIZE = 32
    private val random = SecureRandom()

    fun newChallenge(): ByteArray = ByteArray(SIZE).also { random.nextBytes(it) }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/** First 8 bytes of a key id, grouped for humans, e.g. "3f2a 91c0 7d4e 0b11". */
fun ByteArray.fingerprint(): String = copyOf(8).toHex().chunked(4).joinToString(" ")
