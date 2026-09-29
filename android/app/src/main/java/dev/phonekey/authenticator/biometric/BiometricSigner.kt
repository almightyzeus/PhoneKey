package dev.phonekey.authenticator.biometric

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.Signature

/** A BiometricPrompt that ended without authorizing a signature. */
class BiometricFailedException(val errorCode: Int, message: String) : Exception(message)

/**
 * Signs a message with a Keystore [Signature] after a Class 3 biometric check.
 *
 * The Signature is bound to the prompt through a CryptoObject, so Keystore itself
 * enforces that the fingerprint was verified for this exact operation. PhoneKey
 * never sees biometric data, only the OS's success callback (SECURITY.md G-4).
 */
class BiometricSigner(private val activity: FragmentActivity) {

    fun canAuthenticate(): Int = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)

    fun sign(
        signature: Signature,
        message: ByteArray,
        title: String,
        subtitle: String,
        description: String? = null,
        negativeButton: String = "Cancel",
        onResult: (Result<ByteArray>) -> Unit,
    ) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val authorized = result.cryptoObject?.signature
                if (authorized == null) {
                    onResult(Result.failure(IllegalStateException("Prompt returned no CryptoObject")))
                    return
                }
                onResult(runCatching {
                    authorized.update(message)
                    authorized.sign()
                })
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                onResult(Result.failure(BiometricFailedException(errorCode, errString.toString())))
            }

            // onAuthenticationFailed (unrecognized finger) is not terminal: the prompt stays open.
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .apply { if (description != null) setDescription(description) }
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText(negativeButton)
            .build()

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }
}
