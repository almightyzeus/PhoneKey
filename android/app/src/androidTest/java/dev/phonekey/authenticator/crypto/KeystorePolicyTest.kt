package dev.phonekey.authenticator.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Runs on a real phone with a Class 3 biometric enrolled. These tests never need a
 * finger on the sensor: they check the policy Keystore enforces, and that signing
 * fails when no biometric was given.
 */
@RunWith(AndroidJUnit4::class)
class KeystorePolicyTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val store = DeviceKeyStore(context)

    @After
    fun cleanup() {
        store.deleteKey(ALIAS)
        store.deleteKey(CONTROL_ALIAS)
    }

    @Test
    fun deviceKeyIsHardwareBacked() {
        val key = generateDeviceKey()
        assertNotEquals(KeySecurity.SOFTWARE, key.security)
        assertTrue(store.keyInfo(ALIAS).isUserAuthenticationRequirementEnforcedBySecureHardware)
        Log.i(TAG, "security=${key.security} strongBoxFeature=${store.hasStrongBox()} " +
            "attestationCerts=${key.attestationChain?.size}")
    }

    @Test
    fun teeFallbackWhenStrongBoxAbsent() {
        val key = generateDeviceKey()
        if (!store.hasStrongBox()) {
            assertEquals(KeySecurity.TEE, key.security)
        }
    }

    @Test
    fun keyRequiresFreshStrongBiometricForEverySignature() {
        generateDeviceKey()
        val info = store.keyInfo(ALIAS)
        assertTrue(info.isUserAuthenticationRequired)
        assertEquals(0, info.userAuthenticationValidityDurationSeconds)
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
        assertTrue(info.isInvalidatedByBiometricEnrollment)
        assertEquals(KeyProperties.PURPOSE_SIGN, info.purposes)
    }

    @Test
    fun privateKeyCannotBeExported() {
        generateDeviceKey()
        val key = privateKey(ALIAS)
        assertNull(key.encoded)
        assertThrows(InvalidKeySpecException::class.java) {
            KeyFactory.getInstance("EC", DeviceKeyStore.ANDROID_KEYSTORE)
                .getKeySpec(key, PKCS8EncodedKeySpec::class.java)
        }
    }

    @Test
    fun signingWithoutBiometricIsRefused() {
        generateDeviceKey()
        val failure = runCatching {
            store.signatureFor(ALIAS).run {
                update(Challenges.newChallenge())
                sign()
            }
        }.exceptionOrNull()
        assertNotNull("Keystore signed without a biometric", failure)
        Log.i(TAG, "unauthorized sign refused with: ${causeChain(failure!!)}")
        // Control: the identical code path succeeds for a key without an auth requirement,
        // so the failure above is caused by the biometric policy and nothing else.
        generateControlKey()
        val signature = Signature.getInstance(SignatureVerifier.ALGORITHM).run {
            initSign(privateKey(CONTROL_ALIAS))
            update(Challenges.newChallenge())
            sign()
        }
        assertTrue(signature.isNotEmpty())
    }

    @Test
    fun publicKeyIsExportedAsP256Spki() {
        generateDeviceKey()
        val spki = store.publicKeySpki(ALIAS)
        assertEquals(91, spki.size)
        SignatureVerifier.publicKeyFromSpki(spki) // throws if not P-256
        assertEquals(32, SignatureVerifier.keyId(spki).size)
    }

    /** Keystore's signature format is what the verifier (and later Linux) expects. */
    @Test
    fun keystoreSignaturesVerifyAndTamperingIsDetected() {
        generateControlKey()
        val challenge = Challenges.newChallenge()
        val signature = Signature.getInstance(SignatureVerifier.ALGORITHM).run {
            initSign(privateKey(CONTROL_ALIAS))
            update(challenge)
            sign()
        }
        val spki = KeyStore.getInstance(DeviceKeyStore.ANDROID_KEYSTORE).apply { load(null) }
            .getCertificate(CONTROL_ALIAS).publicKey.encoded
        val publicKey = SignatureVerifier.publicKeyFromSpki(spki)

        assertTrue(SignatureVerifier.verify(publicKey, challenge, signature))
        val badChallenge = challenge.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(SignatureVerifier.verify(publicKey, badChallenge, signature))
        val badSignature = signature.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFalse(SignatureVerifier.verify(publicKey, challenge, badSignature))
    }

    private fun generateDeviceKey(): GeneratedKey {
        assumeTrue(
            "Needs an enrolled Class 3 biometric",
            BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS,
        )
        return store.generate(ALIAS, attestationChallenge = Challenges.newChallenge())
    }

    /** Test-only key with NO auth requirement; never created by app code. */
    private fun generateControlKey() {
        val spec = KeyGenParameterSpec.Builder(CONTROL_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, DeviceKeyStore.ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun privateKey(alias: String): PrivateKey =
        KeyStore.getInstance(DeviceKeyStore.ANDROID_KEYSTORE).apply { load(null) }
            .getKey(alias, null) as PrivateKey

    private fun causeChain(t: Throwable): String =
        generateSequence(t) { it.cause }.joinToString(" <- ") { "${it.javaClass.simpleName}(${it.message})" }

    companion object {
        private const val TAG = "PhoneKeyTest"
        private const val ALIAS = "phonekey.instrumented-test"
        private const val CONTROL_ALIAS = "phonekey.instrumented-control"
    }
}
