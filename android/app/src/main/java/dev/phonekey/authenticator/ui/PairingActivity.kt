package dev.phonekey.authenticator.ui

import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import dev.phonekey.authenticator.R
import dev.phonekey.authenticator.ble.PhoneKeyService
import dev.phonekey.authenticator.biometric.BiometricSigner
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.crypto.fingerprint
import dev.phonekey.authenticator.protocol.AuthenticatorCore
import dev.phonekey.authenticator.protocol.Codec
import dev.phonekey.authenticator.protocol.Labels
import dev.phonekey.authenticator.protocol.PairOffer
import dev.phonekey.authenticator.protocol.VerifierRecord

/**
 * Pairing (PROTOCOL.md §5): the phone advertises in pairing mode, the laptop bonds
 * (numeric comparison on both screens), sends a signed PAIR_REQUEST, and the user
 * confirms here. A new Keystore key is created and its first signature — the proof
 * of possession — needs the fingerprint.
 */
class PairingActivity : AppCompatActivity(), PhoneKeyService.Listener {

    private lateinit var status: TextView
    private lateinit var confirm: Button
    private lateinit var cancel: Button
    private lateinit var keys: DeviceKeyStore
    private var service: PhoneKeyService? = null
    private var offer: PairOffer? = null
    private var finished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)
        status = findViewById(R.id.pairing_status)
        confirm = findViewById(R.id.pairing_confirm)
        cancel = findViewById(R.id.pairing_cancel)
        keys = DeviceKeyStore(this)
        confirm.visibility = View.GONE
        confirm.setOnClickListener { accept() }
        cancel.setOnClickListener {
            if (!finished) service?.cancelPairing()
            finish()
        }

        val s = PhoneKeyService.instance ?: run {
            status.text = "PhoneKey service is not running. Go back and grant the Bluetooth permissions."
            return
        }
        if (getSystemService(android.bluetooth.BluetoothManager::class.java).adapter?.isEnabled != true) {
            status.text = "Bluetooth is off. Turn it on, then tap Add computer again."
            return
        }
        service = s
        s.listeners.add(this)
        s.pendingOffer?.let {
            onPairOffer(it) // the computer is already waiting for us
            return
        }
        s.startPairing() // no-op if a pairing window is already open
        status.text = """
            Pairing mode is on for 2 minutes (you can leave this screen).

            1. On the computer, run:  phonekey pair
            2. Both this phone and the computer will show a 6-digit Bluetooth code.
               Confirm on both ONLY if the codes are identical.
            3. This screen comes back so you can confirm the computer.
        """.trimIndent()
    }

    override fun onDestroy() {
        // Leaving this screen does not cancel pairing: the window stays open in the
        // service (and brings this screen back when the computer asks). Cancel ends it.
        service?.listeners?.remove(this)
        super.onDestroy()
    }

    override fun onPairOffer(offer: PairOffer) {
        this.offer = offer
        status.text = """
            Pair with this computer?

            Computer: ${offer.displayName}
            Account:  ${offer.account}
            Computer key: ${offer.verifierId.fingerprint()}

            Only continue if you just ran `phonekey pair` on this computer.
        """.trimIndent()
        confirm.visibility = View.VISIBLE
    }

    private fun accept() {
        val offer = offer ?: return
        val service = service ?: return
        confirm.isEnabled = false
        val alias = AuthenticatorCore.keyAlias(offer.verifierId)
        try {
            val generated = keys.generate(alias, attestationChallenge = offer.requestHash)
            val spki = keys.publicKeySpki(alias)
            // Attestation is informational only (SECURITY.md D-5); omitted if too large.
            val unsigned = AuthenticatorCore.unsignedPairResponse(offer, spki, phoneName(),
                generated.security.wireValue, generated.attestationChain?.map { it.encoded })
            val record = VerifierRecord(offer.verifierId, offer.verifierKey, offer.displayName, offer.account,
                alias, AuthenticatorCore.sha256(spki), service.pairingAddress())
            BiometricSigner(this).sign(keys.signatureFor(alias), Labels.PAIR_RESPONSE + unsigned,
                "Pair with ${offer.displayName}", "Confirm with your fingerprint") { result ->
                result.fold(
                    onSuccess = { sig ->
                        status.text = "Key created (${generated.security}). Waiting for the computer…"
                        service.submitPairResponse(Codec.withSignature(unsigned, sig), record)
                    },
                    onFailure = { e ->
                        keys.deleteKey(alias)
                        service.cancelPairing()
                        status.text = "Pairing cancelled: ${e.message}"
                    },
                )
            }
        } catch (e: Exception) {
            keys.deleteKey(alias)
            service.cancelPairing()
            status.text = "Could not create a protected key: ${e.message}"
        }
    }

    override fun onPairingFinished(success: Boolean, message: String) {
        finished = true
        confirm.visibility = View.GONE
        cancel.text = "Done"
        status.text = if (success) "✓ $message" else "✗ $message"
    }

    private fun phoneName(): String =
        Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME) ?: Build.MODEL
}
