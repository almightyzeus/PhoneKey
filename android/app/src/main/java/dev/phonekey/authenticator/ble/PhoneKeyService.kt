package dev.phonekey.authenticator.ble

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import dev.phonekey.authenticator.R
import dev.phonekey.authenticator.crypto.DeviceKeyStore
import dev.phonekey.authenticator.crypto.toHex
import dev.phonekey.authenticator.protocol.AuthDecision
import dev.phonekey.authenticator.protocol.AuthenticatorCore
import dev.phonekey.authenticator.protocol.Codec
import dev.phonekey.authenticator.protocol.ErrorCode
import dev.phonekey.authenticator.protocol.Framing
import dev.phonekey.authenticator.protocol.MsgType
import dev.phonekey.authenticator.protocol.PairOffer
import dev.phonekey.authenticator.protocol.ProtocolException
import dev.phonekey.authenticator.protocol.Reassembler
import dev.phonekey.authenticator.protocol.StatusCode
import dev.phonekey.authenticator.protocol.VerifierRecord
import dev.phonekey.authenticator.store.VerifierStore
import dev.phonekey.authenticator.ui.AuthRequestActivity
import dev.phonekey.authenticator.ui.MainActivity
import dev.phonekey.authenticator.ui.PairingActivity
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * The phone is the BLE peripheral (PROTOCOL.md §6.1): a GATT server whose
 * characteristics require an authenticated (MITM-protected) bond, advertised
 * only while a paired laptop is not connected, or during pairing.
 *
 * All state is touched on the main thread; GATT callbacks are posted to it.
 */
@SuppressLint("MissingPermission") // MainActivity obtains BLUETOOTH_CONNECT/ADVERTISE before starting us
class PhoneKeyService : Service() {

    interface Listener {
        fun onPairOffer(offer: PairOffer) {}
        fun onPairingFinished(success: Boolean, message: String) {}
        fun onPromptEnded() {}
    }

    class PromptSession(val address: String, val prompt: AuthDecision.Prompt, val expiry: Runnable)

    private class Link(val device: BluetoothDevice) {
        val rx = Reassembler()
        var mtu = Framing.DEFAULT_ATT_MTU
        var subscribed = false
        val queue = ArrayDeque<ByteArray>()
        var sending = false
    }

    private class PendingPairing(val address: String, val offer: PairOffer) {
        var record: VerifierRecord? = null
    }

    private val main = Handler(Looper.getMainLooper())
    private lateinit var manager: BluetoothManager
    private lateinit var store: VerifierStore
    private var server: BluetoothGattServer? = null
    private var a2v: BluetoothGattCharacteristic? = null
    private val links = mutableMapOf<String, Link>()
    private val subscribedAddresses = ConcurrentHashMap.newKeySet<String>()
    private var advertiseCallback: AdvertiseCallback? = null
    private var advertisingPairing = false
    private var msgNo = 0
    private val rateLog = mutableMapOf<String, ArrayDeque<Long>>()
    private var pendingPairing: PendingPairing? = null
    private val pairingTimeout = Runnable { finishPairing(false, "Pairing timed out") }

    /** Repeats "ready to pair" so it does not matter whether the phone or the laptop opens its window first. */
    private val pairingAnnounce = object : Runnable {
        override fun run() {
            if (!pairingMode || pendingPairing != null) return
            links.values.filter { it.subscribed }.forEach { send(it, AuthenticatorCore.status(StatusCode.READY)) }
            main.postDelayed(this, PAIRING_ANNOUNCE_MS)
        }
    }

    val listeners = mutableSetOf<Listener>()
    var pairingMode = false
        private set
    var activePrompt: PromptSession? = null
        private set
    var isAdvertising = false
        private set

    // ---- lifecycle ---------------------------------------------------------

    override fun onCreate() {
        super.onCreate()
        instance = this
        manager = getSystemService(BluetoothManager::class.java)
        store = VerifierStore(this)
        createChannels()
        startForeground(NOTIFICATION_SERVICE_ID, serviceNotification(),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        registerReceiver(bluetoothState, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
        if (manager.adapter?.isEnabled == true) openServer()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?) = null

    override fun onDestroy() {
        unregisterReceiver(bluetoothState)
        closeServer()
        instance = null
        super.onDestroy()
    }

    private val bluetoothState = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, -1)) {
                BluetoothAdapter.STATE_ON -> openServer()
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> closeServer()
            }
        }
    }

    private fun openServer() {
        if (server != null) return
        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val indicate = BluetoothGattCharacteristic(A2V_UUID, BluetoothGattCharacteristic.PROPERTY_INDICATE, 0).apply {
            addDescriptor(BluetoothGattDescriptor(CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED_MITM or
                    BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED_MITM))
        }
        val write = BluetoothGattCharacteristic(V2A_UUID, BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM)
        service.addCharacteristic(indicate)
        service.addCharacteristic(write)
        a2v = indicate
        server = manager.openGattServer(this, gattCallback)?.also { it.addService(service) }
        if (server == null) Log.e(TAG, "could not open GATT server")
        // Links that outlived a previous instance of this service (the Bluetooth link is
        // shared with other apps) must be adopted, or their requests never reach us.
        manager.getConnectedDevices(BluetoothProfile.GATT_SERVER).forEach { server?.connect(it, false) }
        updateAdvertising()
    }

    private fun closeServer() {
        stopAdvertising()
        activePrompt?.let { endPrompt() }
        if (pairingMode) finishPairing(false, "Bluetooth turned off")
        links.clear()
        subscribedAddresses.clear()
        server?.close()
        server = null
        updateNotification()
    }

    // ---- GATT callbacks (binder threads → main) --------------------------------

    private val gattCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            main.post {
                Log.i(TAG, "link ${device.address}: ${if (newState == BluetoothProfile.STATE_CONNECTED) "connected" else "disconnected"} (status $status)")
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    links.getOrPut(device.address) { Link(device) }
                } else {
                    onDisconnected(device.address)
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            main.post { links[device.address]?.mtu = mtu }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            val ok = descriptor.uuid == CCCD_UUID && !preparedWrite && offset == 0
            if (responseNeeded) {
                server?.sendResponse(device, requestId,
                    if (ok) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, 0, null)
            }
            if (ok) {
                val enabled = value.contentEquals(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
                main.post { onSubscription(device, enabled) }
            }
        }

        override fun onDescriptorReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor,
        ) {
            val value = if (device.address in subscribedAddresses) BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
            else BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, value)
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray,
        ) {
            val ok = characteristic.uuid == V2A_UUID && !preparedWrite && offset == 0
            if (responseNeeded) {
                server?.sendResponse(device, requestId,
                    if (ok) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, 0, null)
            }
            if (ok) {
                val frame = value.copyOf()
                main.post { onFrame(device.address, frame) }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            main.post {
                links[device.address]?.let {
                    it.sending = false
                    if (status != BluetoothGatt.GATT_SUCCESS) it.queue.clear()
                    pump(it)
                }
            }
        }
    }

    // ---- links and messages ------------------------------------------------------

    private fun onSubscription(device: BluetoothDevice, enabled: Boolean) {
        val link = links.getOrPut(device.address) { Link(device) }
        link.subscribed = enabled
        if (enabled) subscribedAddresses.add(device.address) else subscribedAddresses.remove(device.address)
        val record = store.byAddress(device.address)
        Log.i(TAG, "subscription ${device.address}: enabled=$enabled pairingMode=$pairingMode paired=${record != null}")
        if (!enabled) {
            updateAdvertising()
            updateNotification()
            return
        }
        when {
            pairingMode -> send(link, AuthenticatorCore.status(StatusCode.READY)) // no ids: asks for PAIR_REQUEST
            record != null -> send(link, AuthenticatorCore.status(StatusCode.READY, record))
            else -> Log.i(TAG, "subscription from a laptop that is not paired with PhoneKey")
        }
        updateAdvertising()
        updateNotification()
    }

    private fun onDisconnected(address: String) {
        links.remove(address)
        subscribedAddresses.remove(address)
        if (activePrompt?.address == address) endPrompt()
        if (pendingPairing?.address == address) finishPairing(false, "The computer disconnected")
        updateAdvertising()
        updateNotification()
    }

    private fun onFrame(address: String, frame: ByteArray) {
        val link = links[address] ?: return
        val message = try {
            link.rx.feed(frame)
        } catch (e: ProtocolException) {
            send(link, AuthenticatorCore.error(e.error))
            return
        } ?: return
        val msg = try {
            Codec.decode(message)
        } catch (e: ProtocolException) {
            send(link, AuthenticatorCore.error(e.error))
            return
        }
        if (msg.type != MsgType.STATUS) Log.i(TAG, "received ${msg.type} from $address")
        when (msg.type) {
            MsgType.PAIR_REQUEST -> onPairRequest(link, message)
            MsgType.AUTH_REQUEST -> onAuthRequest(link, message)
            MsgType.STATUS -> when (msg.long("status")) {
                StatusCode.PAIRED -> onPaired(link, msg)
                // Laptop keepalive: answer with our ids so it knows this link is alive.
                StatusCode.READY -> store.byAddress(address)?.takeIf {
                    msg.has("verifier_id") && msg.bytes("verifier_id").contentEquals(it.verifierId)
                }?.let { send(link, AuthenticatorCore.status(StatusCode.READY, it)) }
            }
            MsgType.ERROR -> if (pendingPairing?.address == address) {
                val code = ErrorCode.of(msg.long("error_code").toInt())
                finishPairing(false, "The computer refused pairing (${code?.name ?: "error"})")
            }
            else -> send(link, AuthenticatorCore.error(ErrorCode.MALFORMED))
        }
    }

    private fun onAuthRequest(link: Link, data: ByteArray) {
        when (val decision = AuthenticatorCore.evaluateAuthRequest(data) { store.byId(it) }) {
            is AuthDecision.Reply -> send(link, decision.message)
            AuthDecision.Ignore -> Unit
            is AuthDecision.Prompt -> {
                if (activePrompt != null) {
                    send(link, AuthenticatorCore.error(ErrorCode.BUSY, decision.requestId))
                } else if (!allowRate(decision.record)) {
                    send(link, AuthenticatorCore.error(ErrorCode.RATE_LIMITED, decision.requestId))
                } else {
                    val expiry = Runnable { endPrompt() }
                    activePrompt = PromptSession(link.device.address, decision, expiry)
                    main.postDelayed(expiry, decision.ttlMs.coerceIn(1_000, 60_000))
                    showPrompt(decision)
                }
            }
        }
    }

    private fun allowRate(record: VerifierRecord): Boolean {
        val now = System.currentTimeMillis()
        val log = rateLog.getOrPut(record.verifierId.toHex()) { ArrayDeque() }
        while (log.isNotEmpty() && now - log.first() > RATE_WINDOW_MS) log.removeFirst()
        if (log.size >= RATE_LIMIT) return false
        log.addLast(now)
        return true
    }

    private fun send(link: Link, message: ByteArray) {
        if (message[3].toInt() != MsgType.STATUS.code) {
            Log.i(TAG, "sending ${MsgType.of(message[3].toInt())} to ${link.device.address} (${message.size} bytes)")
        }
        msgNo = (msgNo + 1) and 0xFF
        link.queue.addAll(Framing.fragment(message, msgNo, Framing.maxPayload(link.mtu)))
        pump(link)
    }

    private fun pump(link: Link) {
        val characteristic = a2v ?: return
        if (link.sending || link.queue.isEmpty() || !link.subscribed) return
        val status = try {
            server?.notifyCharacteristicChanged(link.device, characteristic, true, link.queue.removeFirst())
        } catch (e: RuntimeException) { // never let a transport error take the service down
            Log.e(TAG, "indication rejected", e)
            null
        }
        if (status == BluetoothStatusCodes.SUCCESS) {
            link.sending = true
        } else {
            Log.w(TAG, "indication failed: $status")
            link.queue.clear()
        }
    }

    // ---- authentication prompts ------------------------------------------------------

    /** Called by AuthRequestActivity with the signed AUTH_RESPONSE. */
    fun completePrompt(response: ByteArray) {
        val session = activePrompt ?: return
        links[session.address]?.let { send(it, response) }
        endPrompt()
    }

    fun failPrompt(code: ErrorCode) {
        val session = activePrompt ?: return
        links[session.address]?.let { send(it, AuthenticatorCore.error(code, session.prompt.requestId)) }
        endPrompt()
    }

    private fun endPrompt() {
        val session = activePrompt ?: return
        main.removeCallbacks(session.expiry)
        activePrompt = null
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_PROMPT_ID)
        listeners.toList().forEach { it.onPromptEnded() }
    }

    private fun showPrompt(prompt: AuthDecision.Prompt) {
        val intent = Intent(this, AuthRequestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pending = PendingIntent.getActivity(this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(this, CHANNEL_PROMPT)
            .setSmallIcon(R.drawable.ic_phonekey)
            .setContentTitle("${AuthenticatorCore.describeAction(prompt.action)} on ${prompt.record.displayName}")
            .setContentText("Tap to approve with your fingerprint")
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(pending)
            .setFullScreenIntent(pending, true)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_PROMPT_ID, notification)
        try {
            startActivity(intent) // allowed while our UI is visible; otherwise the notification is used
        } catch (e: RuntimeException) {
            Log.i(TAG, "could not open prompt directly: ${e.message}")
        }
    }

    // ---- pairing -----------------------------------------------------------------------

    fun startPairing() {
        Log.i(TAG, "startPairing: already=$pairingMode subscribedLinks=${links.values.count { it.subscribed }}")
        if (pairingMode) return
        pairingMode = true
        pendingPairing = null
        main.postDelayed(pairingTimeout, PAIRING_WINDOW_MS)
        updateAdvertising()
        main.post(pairingAnnounce) // a laptop that is already connected can start right away
    }

    fun cancelPairing() {
        pendingPairing?.let { p -> links[p.address]?.let { send(it, AuthenticatorCore.error(ErrorCode.USER_DENIED)) } }
        if (pairingMode) finishPairing(false, "Pairing cancelled")
    }

    private fun onPairRequest(link: Link, data: ByteArray) {
        if (!pairingMode || pendingPairing != null) {
            Log.w(TAG, "PAIR_REQUEST refused: pairingMode=$pairingMode pending=${pendingPairing != null}")
            send(link, AuthenticatorCore.error(ErrorCode.NOT_PAIRING))
            return
        }
        val offer = try {
            AuthenticatorCore.parsePairRequest(data)
        } catch (e: ProtocolException) {
            send(link, AuthenticatorCore.error(e.error))
            finishPairing(false, "Invalid pairing request from the computer")
            return
        }
        pendingPairing = PendingPairing(link.device.address, offer)
        if (listeners.isEmpty()) showPairingScreen() else listeners.toList().forEach { it.onPairOffer(offer) }
    }

    /** A pairing request waiting for the user, if any. */
    val pendingOffer: PairOffer? get() = pendingPairing?.takeIf { it.record == null }?.offer

    private fun showPairingScreen() {
        val intent = Intent(this, PairingActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pending = PendingIntent.getActivity(this, 3, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_PAIRING_ID,
            Notification.Builder(this, CHANNEL_PROMPT)
                .setSmallIcon(R.drawable.ic_phonekey)
                .setContentTitle("Pair with ${pendingPairing?.offer?.displayName}?")
                .setContentText("Tap to review the computer and confirm")
                .setContentIntent(pending)
                .setAutoCancel(true)
                .build())
        try {
            startActivity(intent)
        } catch (e: RuntimeException) {
            Log.i(TAG, "could not open pairing screen directly: ${e.message}")
        }
    }

    /** The Bluetooth address of the laptop being paired (metadata for reconnection). */
    fun pairingAddress(): String? = pendingPairing?.address

    /** Called by PairingActivity with the signed PAIR_RESPONSE and the record to keep on success. */
    fun submitPairResponse(response: ByteArray, record: VerifierRecord) {
        val pending = pendingPairing ?: return
        pending.record = record
        links[pending.address]?.let { send(it, response) } ?: finishPairing(false, "The computer disconnected")
    }

    private fun onPaired(link: Link, msg: dev.phonekey.authenticator.protocol.Message) {
        val pending = pendingPairing ?: return
        val record = pending.record ?: return
        if (pending.address != link.device.address || !msg.has("verifier_id") ||
            !msg.bytes("verifier_id").contentEquals(record.verifierId) ||
            !msg.bytes("device_id").contentEquals(record.deviceId)
        ) return
        store.put(record)
        pending.record = null // keep the key
        finishPairing(true, "Paired with ${record.displayName}")
    }

    private fun finishPairing(success: Boolean, message: String) {
        Log.i(TAG, "pairing finished: success=$success ($message)")
        val pending = pendingPairing
        if (!success) pending?.record?.let { DeviceKeyStore(this).deleteKey(it.keyAlias) }
        pairingMode = false
        pendingPairing = null
        main.removeCallbacks(pairingTimeout)
        main.removeCallbacks(pairingAnnounce)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_PAIRING_ID)
        updateAdvertising()
        updateNotification()
        listeners.toList().forEach { it.onPairingFinished(success, message) }
    }

    fun removeVerifier(record: VerifierRecord) {
        store.remove(record.verifierId)
        DeviceKeyStore(this).deleteKey(record.keyAlias)
        updateAdvertising()
        updateNotification()
    }

    fun connectedVerifiers(): List<VerifierRecord> =
        links.values.filter { it.subscribed }.mapNotNull { store.byAddress(it.device.address) }

    // ---- advertising -------------------------------------------------------------------

    private fun updateAdvertising() {
        if (server == null) {
            stopAdvertising()
            return
        }
        val connected = connectedVerifiers().map { it.verifierId.toHex() }.toSet()
        val wanted = pairingMode || store.all().any { it.verifierId.toHex() !in connected }
        if (!wanted) {
            stopAdvertising()
            return
        }
        if (advertiseCallback != null && advertisingPairing == pairingMode) return
        stopAdvertising()
        val advertiser = manager.adapter?.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(if (pairingMode) AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY
            else AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setConnectable(true)
            .setTimeout(0)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(if (pairingMode) PAIRING_ADV_UUID else SERVICE_UUID))
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()
        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                main.post { if (advertiseCallback === this) isAdvertising = true }
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e(TAG, "advertising failed: $errorCode")
                main.post { if (advertiseCallback === this) advertiseCallback = null }
            }
        }
        advertiseCallback = callback
        advertisingPairing = pairingMode
        advertiser.startAdvertising(settings, data, callback)
    }

    private fun stopAdvertising() {
        advertiseCallback?.let { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(it) }
        advertiseCallback = null
        isAdvertising = false
    }

    // ---- notifications -----------------------------------------------------------------

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL_SERVICE, "PhoneKey status",
            NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CHANNEL_PROMPT, "Authentication requests",
            NotificationManager.IMPORTANCE_HIGH))
    }

    private fun serviceNotification(): Notification {
        val connected = if (::store.isInitialized) connectedVerifiers() else emptyList()
        val text = when {
            pairingMode -> "Pairing mode"
            connected.isNotEmpty() -> "Connected to ${connected.joinToString { it.displayName }}"
            else -> "Ready"
        }
        val open = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_phonekey)
            .setContentTitle("PhoneKey")
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_SERVICE_ID, serviceNotification())
    }

    companion object {
        private const val TAG = "PhoneKey"
        val SERVICE_UUID: UUID = UUID.fromString("eb109ed5-92be-4d34-a98d-61bb7f350b41")
        val A2V_UUID: UUID = UUID.fromString("f3c11509-8693-4342-ae5b-8d0f7e6e50fa")
        val V2A_UUID: UUID = UUID.fromString("955060b9-442a-41f4-bea8-251ea1f42f85")
        val PAIRING_ADV_UUID: UUID = UUID.fromString("419b7d95-95a6-441f-a103-eb24d90499e0")
        val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        const val PAIRING_WINDOW_MS = 120_000L
        private const val PAIRING_ANNOUNCE_MS = 5_000L
        private const val RATE_LIMIT = 5
        private const val RATE_WINDOW_MS = 60_000L
        private const val CHANNEL_SERVICE = "status"
        private const val CHANNEL_PROMPT = "auth"
        private const val NOTIFICATION_SERVICE_ID = 1
        private const val NOTIFICATION_PROMPT_ID = 2
        private const val NOTIFICATION_PAIRING_ID = 3

        @Volatile
        var instance: PhoneKeyService? = null
            private set

        fun start(context: Context) {
            context.startForegroundService(Intent(context, PhoneKeyService::class.java))
        }
    }
}
