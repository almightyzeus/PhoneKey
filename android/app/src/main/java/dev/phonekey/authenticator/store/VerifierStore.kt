package dev.phonekey.authenticator.store

import android.content.Context
import dev.phonekey.authenticator.crypto.toHex
import dev.phonekey.authenticator.protocol.VerifierRecord
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Paired laptops, stored in app-private storage (excluded from backup and device
 * transfer). Contains only public data and Keystore aliases, never key material.
 */
class VerifierStore(context: Context) {
    private val file = File(context.filesDir, "verifiers.json")

    @Synchronized
    fun all(): List<VerifierRecord> {
        if (!file.exists()) return emptyList()
        val array = JSONArray(file.readText())
        return (0 until array.length()).map { fromJson(array.getJSONObject(it)) }
    }

    fun byId(verifierId: ByteArray): VerifierRecord? = all().firstOrNull { it.verifierId.contentEquals(verifierId) }

    fun byAddress(address: String): VerifierRecord? = all().firstOrNull { it.address.equals(address, ignoreCase = true) }

    @Synchronized
    fun put(record: VerifierRecord) {
        write(all().filterNot { it.verifierId.contentEquals(record.verifierId) } + record)
    }

    @Synchronized
    fun remove(verifierId: ByteArray) {
        write(all().filterNot { it.verifierId.contentEquals(verifierId) })
    }

    private fun write(records: List<VerifierRecord>) {
        val array = JSONArray()
        records.forEach { array.put(toJson(it)) }
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.writeText(array.toString())
        if (!tmp.renameTo(file)) throw java.io.IOException("could not save paired computers")
    }

    private fun toJson(r: VerifierRecord) = JSONObject()
        .put("verifier_id", r.verifierId.toHex())
        .put("public_key", r.publicKey.toHex())
        .put("display_name", r.displayName)
        .put("account", r.account)
        .put("key_alias", r.keyAlias)
        .put("device_id", r.deviceId.toHex())
        .put("address", r.address ?: JSONObject.NULL)

    private fun fromJson(o: JSONObject) = VerifierRecord(
        verifierId = o.getString("verifier_id").hexToBytes(),
        publicKey = o.getString("public_key").hexToBytes(),
        displayName = o.getString("display_name"),
        account = o.getString("account"),
        keyAlias = o.getString("key_alias"),
        deviceId = o.getString("device_id").hexToBytes(),
        address = if (o.isNull("address")) null else o.getString("address"),
    )
}

fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
