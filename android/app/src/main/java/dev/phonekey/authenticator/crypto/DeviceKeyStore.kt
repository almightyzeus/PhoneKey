package dev.phonekey.authenticator.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/** Hardware protection of a device key. Wire values match PROTOCOL.md tag 0x0E. */
enum class KeySecurity(val wireValue: Int) {
    SOFTWARE(1),
    TEE(2),
    STRONGBOX(3),
}

/** Thrown when Keystore could only produce a software-backed key (SECURITY.md D-3). */
class HardwareKeyUnavailableException(message: String) : Exception(message)

data class GeneratedKey(
    val alias: String,
    val security: KeySecurity,
    /** Attestation chain, leaf first; null if the device could not attest (informational only, D-5). */
    val attestationChain: List<X509Certificate>?,
)

/**
 * Creates and uses PhoneKey device keys in Android Keystore.
 *
 * Every key is ECDSA P-256, sign-only, and requires a fresh Class 3 biometric for
 * each signature (SECURITY.md G-2, G-3, D-3, D-4). There is deliberately no way to
 * create a key with a weaker policy through this class.
 */
class DeviceKeyStore(private val context: Context) {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun hasStrongBox(): Boolean =
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Generates a new device key under [alias], replacing any existing one.
     *
     * StrongBox is tried first when the device advertises it; otherwise, or if
     * StrongBox refuses, the key is created in the TEE. Attestation is requested but
     * never required: if generation with attestation fails, it is retried without.
     * A key that turns out to be software-only is deleted and rejected.
     */
    fun generate(alias: String, attestationChallenge: ByteArray): GeneratedKey {
        deleteKey(alias)
        val backends = if (hasStrongBox()) listOf(true, false) else listOf(false)
        for (strongBox in backends) {
            try {
                val attested = generateWithOptionalAttestation(alias, attestationChallenge, strongBox)
                val security = securityOf(alias)
                if (security == KeySecurity.SOFTWARE) {
                    deleteKey(alias)
                    throw HardwareKeyUnavailableException(
                        "Keystore produced a software-only key; PhoneKey requires TEE or StrongBox."
                    )
                }
                val chain = if (attested) attestationChainOf(alias) else null
                return GeneratedKey(alias, security, chain)
            } catch (e: StrongBoxUnavailableException) {
                Log.i(TAG, "StrongBox unavailable, falling back to TEE")
            }
        }
        throw HardwareKeyUnavailableException("No hardware-backed Keystore available.")
    }

    fun hasKey(alias: String): Boolean = keyStore.containsAlias(alias)

    fun deleteKey(alias: String) {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    /** DER SubjectPublicKeyInfo of the key's public half. */
    fun publicKeySpki(alias: String): ByteArray =
        requireNotNull(keyStore.getCertificate(alias)) { "No key under alias $alias" }.publicKey.encoded

    fun keyInfo(alias: String): KeyInfo {
        val key = privateKey(alias)
        return KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java)
    }

    fun securityOf(alias: String): KeySecurity = when (keyInfo(alias).securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurity.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeySecurity.TEE
        else -> KeySecurity.SOFTWARE
    }

    /**
     * A [Signature] initialized for signing with the device key, to be wrapped in a
     * BiometricPrompt CryptoObject. Using it without a successful biometric fails.
     *
     * @throws android.security.keystore.KeyPermanentlyInvalidatedException if biometric
     *   enrollment changed since the key was created; the key must be re-generated.
     */
    fun signatureFor(alias: String): Signature =
        Signature.getInstance(SignatureVerifier.ALGORITHM).apply { initSign(privateKey(alias)) }

    private fun privateKey(alias: String): PrivateKey =
        requireNotNull(keyStore.getKey(alias, null) as PrivateKey?) { "No key under alias $alias" }

    private fun attestationChainOf(alias: String): List<X509Certificate>? =
        keyStore.getCertificateChain(alias)?.map { it as X509Certificate }

    /** Returns true if the key was generated with attestation. */
    private fun generateWithOptionalAttestation(
        alias: String,
        attestationChallenge: ByteArray,
        strongBox: Boolean,
    ): Boolean {
        try {
            generateKeyPair(spec(alias, strongBox, attestationChallenge))
            return true
        } catch (e: StrongBoxUnavailableException) {
            throw e
        } catch (e: ProviderException) {
            Log.w(TAG, "Key generation with attestation failed; retrying without attestation", e)
            deleteKey(alias)
        }
        generateKeyPair(spec(alias, strongBox, attestationChallenge = null))
        return false
    }

    private fun generateKeyPair(spec: KeyGenParameterSpec) {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun spec(alias: String, strongBox: Boolean, attestationChallenge: ByteArray?) =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // Timeout 0: every single signature needs its own biometric (T-3, T-5).
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true) // SECURITY.md D-4
            .setIsStrongBoxBacked(strongBox)
            .apply { if (attestationChallenge != null) setAttestationChallenge(attestationChallenge) }
            .build()

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TAG = "PhoneKey"
    }
}
