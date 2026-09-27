package dev.phonekey.authenticator.ui

import android.app.KeyguardManager
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import dev.phonekey.authenticator.R
import dev.phonekey.authenticator.ble.PhoneKeyService
import dev.phonekey.authenticator.biometric.BiometricFailedException
import dev.phonekey.authenticator.biometric.BiometricSigner
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.protocol.AuthenticatorCore
import dev.phonekey.authenticator.protocol.Codec
import dev.phonekey.authenticator.protocol.ErrorCode
import dev.phonekey.authenticator.protocol.Labels

/**
 * Shows an authentication request and signs it after BiometricPrompt succeeds
 * (PROTOCOL.md §8.2). The key also requires an unlocked phone (SECURITY.md D-4),
 * so a locked phone is unlocked first.
 */
class AuthRequestActivity : AppCompatActivity(), PhoneKeyService.Listener {

    private var service: PhoneKeyService? = null
    private var session: PhoneKeyService.PromptSession? = null
    private var prompting = false
    private lateinit var message: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        setContentView(R.layout.activity_auth_request)
        message = findViewById(R.id.auth_message)

        service = PhoneKeyService.instance
        session = service?.activePrompt
        val prompt = session?.prompt ?: run {
            finish()
            return
        }
        service?.listeners?.add(this)
        findViewById<TextView>(R.id.auth_details).text = """
            ${prompt.record.displayName}

            Action:
            ${AuthenticatorCore.describeAction(prompt.action)}

            Target: ${prompt.resource}
            Account: ${prompt.account}
        """.trimIndent()
        findViewById<Button>(R.id.auth_approve).setOnClickListener { approve() }
        findViewById<Button>(R.id.auth_deny).setOnClickListener {
            service?.failPrompt(ErrorCode.USER_DENIED)
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        if (!prompting && session != null) approve()
    }

    override fun onDestroy() {
        service?.listeners?.remove(this)
        super.onDestroy()
    }

    override fun onPromptEnded() {
        finish() // timed out, disconnected, or answered
    }

    private fun approve() {
        if (prompting) return
        val keyguard = getSystemService(KeyguardManager::class.java)
        if (keyguard.isKeyguardLocked) {
            message.text = "Unlock your phone to continue."
            keyguard.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
                override fun onDismissSucceeded() = showBiometric()
            })
        } else {
            showBiometric()
        }
    }

    private fun showBiometric() {
        val service = service ?: return
        val prompt = session?.prompt ?: return
        if (service.activePrompt !== session) {
            finish()
            return
        }
        val signature = try {
            DeviceKeyStore(this).signatureFor(prompt.record.keyAlias)
        } catch (e: KeyPermanentlyInvalidatedException) {
            message.text = "Fingerprints changed since pairing. Pair this computer again."
            service.failPrompt(ErrorCode.KEY_INVALIDATED)
            return
        } catch (e: Exception) {
            message.text = "PhoneKey key unavailable: ${e.message}"
            service.failPrompt(ErrorCode.INTERNAL)
            return
        }
        prompting = true
        message.text = ""
        BiometricSigner(this).sign(signature, Labels.AUTH_ASSERTION + prompt.unsignedResponse,
            "${AuthenticatorCore.describeAction(prompt.action)}", "${prompt.record.displayName} · ${prompt.account}",
        ) { result ->
            prompting = false
            result.fold(
                onSuccess = { sig ->
                    service.completePrompt(Codec.withSignature(prompt.unsignedResponse, sig))
                    finish()
                },
                onFailure = { e ->
                    val cancelled = e is BiometricFailedException && e.errorCode in setOf(
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_USER_CANCELED)
                    if (cancelled) {
                        message.text = "Cancelled. Tap Approve to try again, or Deny."
                    } else {
                        service.failPrompt(ErrorCode.BIOMETRIC_FAILED)
                        message.text = "Not approved: ${e.message}"
                    }
                },
            )
        }
    }
}
