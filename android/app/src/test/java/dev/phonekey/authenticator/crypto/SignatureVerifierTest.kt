package dev.phonekey.authenticator.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Verification logic, run on the JVM with software keys. The same verifier checks
 * real Keystore signatures in KeystorePolicyTest (instrumented).
 */
class SignatureVerifierTest {

    private val keyPair = newKeyPair("secp256r1")
    private val publicKey = SignatureVerifier.publicKeyFromSpki(keyPair.public.encoded)
    private val challenge = Challenges.newChallenge()
    private val signature = sign(keyPair, challenge)

    @Test
    fun validSignatureVerifies() {
        assertTrue(SignatureVerifier.verify(publicKey, challenge, signature))
    }

    @Test
    fun modifiedChallengeFails() {
        for (i in challenge.indices) {
            val modified = challenge.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            assertFalse("byte $i", SignatureVerifier.verify(publicKey, modified, signature))
        }
        assertFalse(SignatureVerifier.verify(publicKey, challenge + 0, signature))
        assertFalse(SignatureVerifier.verify(publicKey, challenge.copyOf(challenge.size - 1), signature))
    }

    @Test
    fun modifiedSignatureFails() {
        for (i in signature.indices) {
            val modified = signature.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            assertFalse("byte $i", SignatureVerifier.verify(publicKey, challenge, modified))
        }
    }

    @Test
    fun malformedSignatureFailsWithoutThrowing() {
        assertFalse(SignatureVerifier.verify(publicKey, challenge, ByteArray(0)))
        assertFalse(SignatureVerifier.verify(publicKey, challenge, ByteArray(64)))
        assertFalse(SignatureVerifier.verify(publicKey, challenge, signature.copyOf(signature.size - 1)))
        assertFalse(SignatureVerifier.verify(publicKey, challenge, signature + 0))
    }

    @Test
    fun signatureFromAnotherKeyFails() {
        val otherSignature = sign(newKeyPair("secp256r1"), challenge)
        assertFalse(SignatureVerifier.verify(publicKey, challenge, otherSignature))
    }

    @Test
    fun nonP256KeysAreRejected() {
        val p384 = newKeyPair("secp384r1").public.encoded
        assertThrows(IllegalArgumentException::class.java) { SignatureVerifier.publicKeyFromSpki(p384) }

        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertThrows(IllegalArgumentException::class.java) {
            SignatureVerifier.publicKeyFromSpki(rsa.public.encoded)
        }
    }

    @Test
    fun malformedSpkiIsRejected() {
        val spki = keyPair.public.encoded
        assertThrows(IllegalArgumentException::class.java) { SignatureVerifier.publicKeyFromSpki(ByteArray(0)) }
        assertThrows(IllegalArgumentException::class.java) {
            SignatureVerifier.publicKeyFromSpki(spki.copyOf(spki.size - 1))
        }
    }

    @Test
    fun p256SpkiIs91Bytes() {
        // PROTOCOL.md tag 0x0A fixes the public_key size at 91 bytes.
        assertEquals(91, keyPair.public.encoded.size)
    }

    @Test
    fun keyIdIsSha256OfSpki() {
        val spki = keyPair.public.encoded
        val id = SignatureVerifier.keyId(spki)
        assertEquals(32, id.size)
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(spki), id)
    }

    @Test
    fun challengesAreFreshAndFullLength() {
        val seen = HashSet<String>()
        repeat(1000) {
            val c = Challenges.newChallenge()
            assertEquals(32, c.size)
            assertTrue("duplicate challenge", seen.add(c.toHex()))
        }
    }

    private fun newKeyPair(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair()

    private fun sign(keyPair: KeyPair, message: ByteArray): ByteArray =
        Signature.getInstance(SignatureVerifier.ALGORITHM).run {
            initSign(keyPair.private)
            update(message)
            sign()
        }
}
