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
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.crypto.fingerprint
import dev.phonekey.authenticator.crypto.toHex
import dev.phonekey.authenticator.protocol.VerifierRecord
import dev.phonekey.authenticator.store.VerifierStore

/** Status, paired computers, and a one-line summary of the phone's security features. */
class MainActivity : AppCompatActivity() {

    private lateinit var keys: DeviceKeyStore
    private lateinit var statusText: TextView
    private lateinit var statusHint: TextView
    private lateinit var pairedList: LinearLayout
    private lateinit var fullScreenButton: Button
    private lateinit var bluetoothButton: Button
    private lateinit var messageText: TextView
    private lateinit var deviceText: TextView
    private var armedRemoval: String? = null // verifier id hex awaiting the second tap
    private val handler = Handler(Looper.getMainLooper())
    private val disarm = Runnable { armedRemoval = null; refresh() }
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
        keys.deleteKey(OLD_TEST_ALIAS) // left over from the Phase 1 diagnostics
        statusText = findViewById(R.id.status_text)
        statusHint = findViewById(R.id.status_hint)
        pairedList = findViewById(R.id.paired_list)
        messageText = findViewById(R.id.message_text)
        deviceText = findViewById(R.id.device_text)
        fullScreenButton = findViewById(R.id.full_screen_button)
        bluetoothButton = findViewById(R.id.bluetooth_button)
        bluetoothButton.setOnClickListener {
            startActivity(Intent(android.bluetooth.BluetoothAdapter.ACTION_REQUEST_ENABLE))
        }
        findViewById<Button>(R.id.add_computer_button).setOnClickListener {
            startActivity(Intent(this, PairingActivity::class.java))
        }
        fullScreenButton.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                    android.net.Uri.parse("package:$packageName")))
            }
        }
        deviceText.text = deviceSummary()

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
        handler.removeCallbacks(disarm)
        armedRemoval = null
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
        val records = VerifierStore(this).all()
        val connected = service?.connectedVerifiers()?.map { it.verifierId.toHex() }?.toSet() ?: emptySet()
        val bluetoothOn = getSystemService(android.bluetooth.BluetoothManager::class.java).adapter?.isEnabled == true
        bluetoothButton.visibility = if (bluetoothOn) View.GONE else View.VISIBLE

        val connectedNames = records.filter { it.verifierId.toHex() in connected }.joinToString { it.displayName }
        val (status, hint) = when {
            service == null -> getString(R.string.status_not_running) to getString(R.string.hint_not_running)
            !bluetoothOn -> getString(R.string.status_bluetooth_off) to getString(R.string.hint_bluetooth_off)
            service.pairingMode -> getString(R.string.status_pairing) to getString(R.string.hint_pairing)
            connectedNames.isNotEmpty() ->
                getString(R.string.status_connected, connectedNames) to getString(R.string.hint_connected)
            records.isNotEmpty() -> getString(R.string.status_waiting, records.joinToString { it.displayName }) to
                getString(R.string.hint_waiting)
            else -> getString(R.string.status_unpaired) to getString(R.string.hint_unpaired)
        }
        statusText.text = status
        statusHint.text = hint

        pairedList.removeAllViews()
        if (records.isEmpty()) {
            pairedList.addView(TextView(this).apply { text = getString(R.string.no_computers) })
        }
        for (record in records) pairedList.addView(row(record, record.verifierId.toHex() in connected))

        // Android 14+ lets the user revoke full-screen prompts; on 13 they are granted at install.
        val canFullScreen = Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE ||
            getSystemService(NotificationManager::class.java).canUseFullScreenIntent()
        fullScreenButton.visibility = if (canFullScreen) View.GONE else View.VISIBLE
    }

    private fun row(record: VerifierRecord, isConnected: Boolean): View {
        val id = record.verifierId.toHex()
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 12, 0, 12)
        }
        row.addView(TextView(this).apply {
            val state = getString(if (isConnected) R.string.state_connected else R.string.state_not_connected)
            text = getString(R.string.computer_row, record.displayName, state, record.account,
                record.verifierId.fingerprint())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        row.addView(Button(this).apply {
            text = getString(if (armedRemoval == id) R.string.remove_confirm else R.string.remove)
            setOnClickListener {
                if (armedRemoval != id) { // first tap: ask to confirm, for 4 seconds
                    armedRemoval = id
                    handler.removeCallbacks(disarm)
                    handler.postDelayed(disarm, 4_000)
                } else {
                    armedRemoval = null
                    handler.removeCallbacks(disarm)
                    remove(record)
                }
                refresh()
            }
        })
        return row
    }

    private fun remove(record: VerifierRecord) {
        PhoneKeyService.instance?.removeVerifier(record)
            ?: run { VerifierStore(this).remove(record.verifierId); keys.deleteKey(record.keyAlias) }
        messageText.text = getString(R.string.removed, record.displayName)
    }

    private fun deviceSummary(): String {
        val fingerprint = getString(when (BiometricSigner(this).canAuthenticate()) {
            BiometricManager.BIOMETRIC_SUCCESS -> R.string.fingerprint_ready
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> R.string.fingerprint_none_enrolled
            else -> R.string.fingerprint_unavailable
        })
        val storage = getString(if (keys.hasStrongBox()) R.string.keys_strongbox else R.string.keys_tee)
        return getString(R.string.device_summary, fingerprint, storage)
    }

    private companion object {
        const val OLD_TEST_ALIAS = "phonekey.phase1-test"
    }
}
