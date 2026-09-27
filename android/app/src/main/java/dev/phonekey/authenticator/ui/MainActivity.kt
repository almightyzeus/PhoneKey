package dev.phonekey.authenticator.ui

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import dev.phonekey.authenticator.R
import dev.phonekey.authenticator.biometric.BiometricSigner
import dev.phonekey.authenticator.ble.PhoneKeyService
import dev.phonekey.authenticator.crypto.Challenges
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.crypto.SignatureVerifier
import dev.phonekey.authenticator.crypto.fingerprint
import dev.phonekey.authenticator.crypto.toHex
import dev.phonekey.authenticator.store.VerifierStore

/** Status, paired computers, and the Phase 1 key diagnostics. */
class MainActivity : AppCompatActivity() {

    private lateinit var keys: DeviceKeyStore
    private lateinit var signer: BiometricSigner
    private lateinit var statusText: TextView
    private lateinit var pairedList: LinearLayout
    private lateinit var fullScreenButton: Button
    private lateinit var bluetoothButton: Button
    private lateinit var deviceText: TextView
    private lateinit var outputText: TextView
    private val handler = Handler(Looper.getMainLooper())
    private val refresher = object : Runnable {
        override fun run() {
            refresh()
            handler.postDelayed(this, 2_000)
        }
    }

    private val permissions = arrayOf(
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.POST_NOTIFICATIONS,
    )
    private val permissionRequest = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        startServiceIfAllowed()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        keys = DeviceKeyStore(this)
        signer = BiometricSigner(this)
        statusText = findViewById(R.id.status_text)
        pairedList = findViewById(R.id.paired_list)
        fullScreenButton = findViewById(R.id.full_screen_button)
        bluetoothButton = findViewById(R.id.bluetooth_button)
        bluetoothButton.setOnClickListener {
            startActivity(Intent(android.bluetooth.BluetoothAdapter.ACTION_REQUEST_ENABLE))
        }
        deviceText = findViewById(R.id.device_text)
        outputText = findViewById(R.id.output_text)

        findViewById<Button>(R.id.add_computer_button).setOnClickListener {
            startActivity(Intent(this, PairingActivity::class.java))
        }
        fullScreenButton.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                    android.net.Uri.parse("package:$packageName")))
            }
        }
        findViewById<Button>(R.id.generate_button).setOnClickListener { generateKey() }
        findViewById<Button>(R.id.sign_button).setOnClickListener { signTestChallenge() }
        findViewById<Button>(R.id.sign_unauthorized_button).setOnClickListener { signWithoutBiometric() }
        findViewById<Button>(R.id.delete_button).setOnClickListener {
            keys.deleteKey(TEST_ALIAS)
            show("Test key deleted.")
        }

        if (permissions.all { checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }) {
            startServiceIfAllowed()
        } else {
            permissionRequest.launch(permissions)
        }
    }

    override fun onResume() {
        super.onResume()
        handler.post(refresher)
    }

    override fun onPause() {
        handler.removeCallbacks(refresher)
        super.onPause()
    }

    private fun startServiceIfAllowed() {
        val bluetoothGranted = listOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
            .all { checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
        if (bluetoothGranted) PhoneKeyService.start(this)
        refresh()
    }

    private fun refresh() {
        val service = PhoneKeyService.instance
        val connected = service?.connectedVerifiers()?.map { it.verifierId.toHex() }?.toSet() ?: emptySet()
        val bluetoothOn = getSystemService(android.bluetooth.BluetoothManager::class.java).adapter?.isEnabled == true
        bluetoothButton.visibility = if (bluetoothOn) View.GONE else View.VISIBLE
        statusText.text = when {
            service == null -> "● PhoneKey is not running — Bluetooth permissions are needed."
            !bluetoothOn -> "● Bluetooth is off. Turn it on to use PhoneKey."
            service.pairingMode -> "● Pairing mode"
            connected.isNotEmpty() -> "● Connected"
            service.isAdvertising -> "○ Waiting for your computer"
            else -> "○ Ready (no computer paired)"
        }

        pairedList.removeAllViews()
        val records = VerifierStore(this).all()
        if (records.isEmpty()) {
            pairedList.addView(TextView(this).apply { text = "No computers paired yet." })
        }
        for (record in records) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            row.addView(TextView(this).apply {
                val state = if (record.verifierId.toHex() in connected) "connected" else "not connected"
                text = "${record.displayName} (${record.account})\n${record.verifierId.fingerprint()} · $state"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            row.addView(Button(this).apply {
                text = "Remove"
                setOnClickListener {
                    service?.removeVerifier(record)
                        ?: run { VerifierStore(this@MainActivity).remove(record.verifierId); keys.deleteKey(record.keyAlias) }
                    show("Removed ${record.displayName}. Also run `phonekey unpair` on the computer and forget " +
                        "the computer in Android Bluetooth settings.")
                    refresh()
                }
            })
            pairedList.addView(row)
        }

        // Android 14+ lets the user revoke full-screen prompts; on 13 they are granted at install.
        val canFullScreen = Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            getSystemService(NotificationManager::class.java).canUseFullScreenIntent()
        fullScreenButton.visibility = if (canFullScreen) View.GONE else View.VISIBLE
        refreshDeviceReport()
    }

    // ---- diagnostics (Phase 1 local crypto test) -----------------------------------

    private fun refreshDeviceReport() {
        val biometric = when (signer.canAuthenticate()) {
            BiometricManager.BIOMETRIC_SUCCESS -> "available"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none enrolled"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "no Class 3 hardware"
            else -> "unavailable"
        }
        val key = if (keys.hasKey(TEST_ALIAS)) {
            "${keys.securityOf(TEST_ALIAS)} · ${SignatureVerifier.keyId(keys.publicKeySpki(TEST_ALIAS)).fingerprint()}"
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
            val attestation = generated.attestationChain?.let { "${it.size} certificates (informational)" }
                ?: "not available (informational)"
            show("Generated key in ${generated.security}.\nAttestation: $attestation")
        } catch (e: Exception) {
            show("Key generation failed: ${e.javaClass.simpleName}: ${e.message}")
        }
        refreshDeviceReport()
    }

    private fun signTestChallenge() {
        if (!keys.hasKey(TEST_ALIAS)) return show("Generate a key first.")
        val challenge = Challenges.newChallenge()
        val signature = try {
            keys.signatureFor(TEST_ALIAS)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return show("Key was invalidated (biometric enrollment changed). Generate a new key.")
        }
        signer.sign(signature, challenge, "PhoneKey test", "Sign a local test challenge") { result ->
            result.fold(
                onSuccess = { sig ->
                    val publicKey = SignatureVerifier.publicKeyFromSpki(keys.publicKeySpki(TEST_ALIAS))
                    val badChallenge = challenge.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                    val badSig = sig.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
                    show("""
                        ${mark(SignatureVerifier.verify(publicKey, challenge, sig))} valid signature verifies
                        ${mark(!SignatureVerifier.verify(publicKey, badChallenge, sig))} modified challenge rejected
                        ${mark(!SignatureVerifier.verify(publicKey, challenge, badSig))} modified signature rejected
                    """.trimIndent())
                },
                onFailure = { e -> show("Not signed: ${e.message}") },
            )
        }
    }

    private fun signWithoutBiometric() {
        if (!keys.hasKey(TEST_ALIAS)) return show("Generate a key first.")
        val outcome = runCatching {
            keys.signatureFor(TEST_ALIAS).run { update(Challenges.newChallenge()); sign() }
        }
        show(outcome.fold(
            onSuccess = { "✗ UNEXPECTED: Keystore signed without a biometric!" },
            onFailure = { "✓ Keystore refused to sign without a biometric (${it.javaClass.simpleName})." },
        ))
    }

    private fun mark(ok: Boolean) = if (ok) "✓" else "✗"

    private fun show(message: String) {
        outputText.text = message
    }

    companion object {
        const val TEST_ALIAS = "phonekey.phase1-test"
    }
}
