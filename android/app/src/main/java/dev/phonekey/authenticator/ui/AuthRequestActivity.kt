package dev.phonekey.authenticator.ui

import android.app.KeyguardManager
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import android.view.View
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
import java.security.Signature

/**
 * Shows an authentication request and signs it after BiometricPrompt succeeds
 * (PROTOCOL.md §8.2). Works over the lock screen: the fingerprint prompt is the
 * authorization (SECURITY.md D-4). If the system refuses to show the prompt while
 * locked, the phone is unlocked first.
 */
class AuthRequestActivity : AppCompatActivity(), PhoneKeyService.Listener {

    private var service: PhoneKeyService? = null
    private var session: PhoneKeyService.PromptSession? = null
    private var prompting = false
    private var triedLocked = false // the prompt was attempted over the lock screen
    private lateinit var details: TextView
    private lateinit var message: TextView
    private lateinit var approveButton: Button
    private lateinit var keyguard: KeyguardManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        setContentView(R.layout.activity_auth_request)
        details = findViewById(R.id.auth_details)
        message = findViewById(R.id.auth_message)
        approveButton = findViewById(R.id.auth_approve)
        keyguard = getSystemService(KeyguardManager::class.java)

        service = PhoneKeyService.instance
        session = service?.activePrompt
        val prompt = session?.prompt ?: run {
            finish()
            return
        }
        service?.listeners?.add(this)
        details.text = """
            ${prompt.record.displayName}

            Action:
            ${AuthenticatorCore.describeAction(prompt.action)}

            Target: ${prompt.resource}
            Account: ${prompt.account}
        """.trimIndent()
        approveButton.setOnClickListener { approve() }
        findViewById<Button>(R.id.auth_deny).setOnClickListener {
            service?.failPrompt(ErrorCode.USER_DENIED)
            finish()
        }
    }

    override fun onResume() {
        super.onResume()
        if (!prompting && session != null && !triedLocked) approve()
    }

    override fun onDestroy() {
        service?.listeners?.remove(this)
        super.onDestroy()
    }

    override fun onPromptEnded() {
        finish() // timed out, disconnected, or answered
    }

    private fun showLocked() {
        details.visibility = View.GONE // no request details on the lock screen
        message.text = "PhoneKey request. Unlock your phone to review it."
        approveButton.text = getString(R.string.auth_unlock)
    }

    private fun showUnlocked() {
        details.visibility = View.VISIBLE
        message.text = ""
        approveButton.text = getString(R.string.auth_approve)
    }

    private fun requestUnlock() {
        keyguard.requestDismissKeyguard(this, object : KeyguardManager.KeyguardDismissCallback() {
            override fun onDismissSucceeded() {
                showUnlocked()
                approve()
            }

            override fun onDismissCancelled() {
                message.text = "Unlock your phone to review this request, or Deny."
            }
        })
    }

    private fun approve() {
        if (prompting) return
        if (keyguard.isKeyguardLocked && triedLocked) {
            requestUnlock() // the prompt could not be shown over the lock screen
            return
        }
        if (keyguard.isKeyguardLocked) triedLocked = true
        showUnlocked()
        openKeyThenPrompt(attempt = 0)
    }

    /**
     * Keystore learns about the unlock slightly after the keyguard is dismissed, so
     * UserNotAuthenticatedException right after unlocking is retried briefly.
     */
    private fun openKeyThenPrompt(attempt: Int) {
        val service = service ?: return
        val prompt = session?.prompt ?: return
        if (service.activePrompt !== session) {
            finish()
            return
        }
        val signature = try {
            DeviceKeyStore(this).signatureFor(prompt.record.keyAlias)
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.w(TAG, "device key invalidated", e)
            message.text = "Fingerprints changed since pairing. Pair this computer again."
            service.failPrompt(ErrorCode.KEY_INVALIDATED)
            return
        } catch (e: UserNotAuthenticatedException) {
            if (attempt < UNLOCK_RETRIES) {
                message.text = "Waiting for the phone to finish unlocking…"
                window.decorView.postDelayed({ openKeyThenPrompt(attempt + 1) }, UNLOCK_RETRY_MS)
            } else {
                Log.e(TAG, "device key still locked after unlocking", e)
                message.text = "The key is still locked. Unlock the phone and tap Approve."
            }
            return
        } catch (e: Exception) {
            Log.e(TAG, "cannot use device key ${prompt.record.keyAlias}", e)
            message.text = "PhoneKey key unavailable: ${e.javaClass.simpleName}: ${e.message}"
            service.failPrompt(ErrorCode.INTERNAL)
            return
        }
        showBiometric(signature)
    }

    private fun showBiometric(signature: Signature) {
        val service = service ?: return
        val prompt = session?.prompt ?: return
        prompting = true
        message.text = ""
        BiometricSigner(this).sign(signature, Labels.AUTH_ASSERTION + prompt.unsignedResponse,
            AuthenticatorCore.describeAction(prompt.action), "${prompt.record.displayName} · ${prompt.account}",
        ) { result ->
            prompting = false
            result.fold(
                onSuccess = { sig ->
                    service.completePrompt(Codec.withSignature(prompt.unsignedResponse, sig))
                    finish()
                },
                onFailure = { e ->
                    Log.w(TAG, "signature not produced", e)
                    val cancelled = e is BiometricFailedException && e.errorCode in setOf(
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_USER_CANCELED)
                    if (cancelled) {
                        message.text = "Cancelled. Tap Approve to try again, or Deny."
                    } else if (keyguard.isKeyguardLocked && e is BiometricFailedException &&
                        e.errorCode !in setOf(BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT)
                    ) {
                        Log.i(TAG, "prompt unavailable over the lock screen; unlocking first", e)
                        requestUnlock()
                    } else {
                        service.failPrompt(ErrorCode.BIOMETRIC_FAILED)
                        message.text = "Not approved: ${e.message}"
                    }
                },
            )
        }
    }

    private companion object {
        const val TAG = "PhoneKey"
        const val UNLOCK_RETRIES = 15
        const val UNLOCK_RETRY_MS = 200L
    }
}
