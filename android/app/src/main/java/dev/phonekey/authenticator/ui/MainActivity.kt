package dev.phonekey.authenticator.ui

import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import dev.phonekey.authenticator.R
import dev.phonekey.authenticator.biometric.BiometricSigner
import dev.phonekey.authenticator.crypto.Challenges
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.crypto.SignatureVerifier
import dev.phonekey.authenticator.crypto.fingerprint
import dev.phonekey.authenticator.crypto.toHex

/**
 * Phase 1 local test flow (no BLE):
 * challenge → BiometricPrompt → Keystore signature → verification with the public key.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var keys: DeviceKeyStore
    private lateinit var signer: BiometricSigner
    private lateinit var deviceText: TextView
    private lateinit var outputText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        keys = DeviceKeyStore(this)
        signer = BiometricSigner(this)
        deviceText = findViewById(R.id.device_text)
        outputText = findViewById(R.id.output_text)

        findViewById<Button>(R.id.generate_button).setOnClickListener { generateKey() }
        findViewById<Button>(R.id.sign_button).setOnClickListener { signTestChallenge() }
        findViewById<Button>(R.id.sign_unauthorized_button).setOnClickListener { signWithoutBiometric() }
        findViewById<Button>(R.id.delete_button).setOnClickListener {
            keys.deleteKey(TEST_ALIAS)
            show("Test key deleted.")
        }
    }

    override fun onResume() {
        super.onResume()
        refreshDeviceReport()
    }

    private fun refreshDeviceReport() {
        val biometric = when (signer.canAuthenticate()) {
            BiometricManager.BIOMETRIC_SUCCESS -> "available"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none enrolled"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no Class 3 hardware"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "hardware unavailable"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "security update required"
            else -> "unavailable"
        }
        val key = if (keys.hasKey(TEST_ALIAS)) {
            val id = SignatureVerifier.keyId(keys.publicKeySpki(TEST_ALIAS))
            "${keys.securityOf(TEST_ALIAS)} · ${id.fingerprint()}"
        } else {
            "none"
        }
        deviceText.text = """
            Device: ${Build.MANUFACTURER} ${Build.MODEL}
            Android: ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})
            StrongBox feature: ${if (keys.hasStrongBox()) "yes" else "no"}
            Class 3 biometric: $biometric
            Test key: $key
        """.trimIndent()
    }

    private fun generateKey() {
        try {
            val generated = keys.generate(TEST_ALIAS, attestationChallenge = Challenges.newChallenge())
            val attestation = generated.attestationChain
                ?.let { "${it.size} certificates (informational)" }
                ?: "not available (informational)"
            show(
                "Generated key in ${generated.security}.\n" +
                    "Public key id: ${SignatureVerifier.keyId(keys.publicKeySpki(TEST_ALIAS)).fingerprint()}\n" +
                    "Attestation: $attestation"
            )
        } catch (e: Exception) {
            show("Key generation failed: ${e.javaClass.simpleName}: ${e.message}")
        }
        refreshDeviceReport()
    }

    private fun signTestChallenge() {
        if (!keys.hasKey(TEST_ALIAS)) {
            show("Generate a key first.")
            return
        }
        val challenge = Challenges.newChallenge()
        val signature = try {
            keys.signatureFor(TEST_ALIAS)
        } catch (e: KeyPermanentlyInvalidatedException) {
            show("Key was invalidated (biometric enrollment changed). Generate a new key.")
            return
        }
        signer.sign(signature, challenge, "PhoneKey test", "Sign a local test challenge") { result ->
            result.fold(
                onSuccess = { sig -> showVerification(challenge, sig) },
                onFailure = { e -> show("Not signed: ${e.message}") },
            )
        }
    }

    private fun showVerification(challenge: ByteArray, signature: ByteArray) {
        val publicKey = SignatureVerifier.publicKeyFromSpki(keys.publicKeySpki(TEST_ALIAS))
        val valid = SignatureVerifier.verify(publicKey, challenge, signature)
        val tamperedChallenge = challenge.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        val tamperedSignature = signature.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte() }
        val challengeRejected = !SignatureVerifier.verify(publicKey, tamperedChallenge, signature)
        val signatureRejected = !SignatureVerifier.verify(publicKey, challenge, tamperedSignature)
        show(
            """
            Challenge: ${challenge.toHex().take(16)}…
            Signature: ${signature.size} bytes

            ${mark(valid)} valid signature verifies
            ${mark(challengeRejected)} modified challenge rejected
            ${mark(signatureRejected)} modified signature rejected
            """.trimIndent()
        )
    }

    /** Demonstrates that Keystore refuses to sign without a biometric (T-5). */
    private fun signWithoutBiometric() {
        if (!keys.hasKey(TEST_ALIAS)) {
            show("Generate a key first.")
            return
        }
        val outcome = runCatching {
            keys.signatureFor(TEST_ALIAS).run {
                update(Challenges.newChallenge())
                sign()
            }
        }
        show(
            outcome.fold(
                onSuccess = { "✗ UNEXPECTED: Keystore signed without a biometric!" },
                onFailure = { "✓ Keystore refused to sign without a biometric (${it.javaClass.simpleName})." },
            )
        )
    }

    private fun mark(ok: Boolean) = if (ok) "✓" else "✗"

    private fun show(message: String) {
        outputText.text = message
    }

    companion object {
        /** Phase 1 test key; separate from any future per-verifier device key. */
        const val TEST_ALIAS = "phonekey.phase1-test"
    }
}
