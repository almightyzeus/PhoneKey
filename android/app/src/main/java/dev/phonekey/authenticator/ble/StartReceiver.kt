package dev.phonekey.authenticator.ble

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import dev.phonekey.authenticator.store.VerifierStore

/**
 * Starts PhoneKeyService after the phone boots (after its first unlock) and
 * after the app is updated, so paired computers reconnect without opening the
 * app. Not exported: only the system can deliver these broadcasts to it.
 *
 * Starts nothing unless a computer is paired and the Bluetooth permissions are
 * granted. Starting the service grants nothing: every signature still needs a
 * fingerprint (SECURITY.md D-14).
 */
class StartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action !in ACTIONS) return
        val permitted = listOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
            .all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
        if (!permitted || VerifierStore(context).all().isEmpty()) {
            Log.i(TAG, "not starting after ${intent.action}: ${if (permitted) "nothing paired" else "no permission"}")
            return
        }
        Log.i(TAG, "starting after ${intent.action}")
        try {
            PhoneKeyService.start(context)
        } catch (e: RuntimeException) { // e.g. ForegroundServiceStartNotAllowedException
            Log.w(TAG, "could not start after ${intent.action}; open the app to start it", e)
        }
    }

    private companion object {
        const val TAG = "PhoneKey"
        val ACTIONS = setOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED)
    }
}
