package dev.phonekey.authenticator.protocol

import dev.phonekey.authenticator.crypto.SignatureVerifier
import dev.phonekey.authenticator.crypto.toHex
import dev.phonekey.authenticator.store.hexToBytes
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** protocol/test-vectors/v1.json: the same file the Python implementation must pass. */
class CodecVectorTest {
    private val vectors = JSONObject(
        javaClass.classLoader!!.getResourceAsStream("v1.json")!!.bufferedReader().readText()
    )
    private val labels = mapOf(
        "pair-request" to Labels.PAIR_REQUEST, "pair-response" to Labels.PAIR_RESPONSE,
        "auth-request" to Labels.AUTH_REQUEST, "auth-assertion" to Labels.AUTH_ASSERTION,
    )

    private fun fields(json: JSONObject): Map<String, Any> = json.keys().asSequence().toList().associateWith { name ->
        when (Codec.byName.getValue(name).kind) {
            Kind.BYTES -> json.getString(name).hexToBytes()
            Kind.STRING -> json.getString(name)
            else -> json.getLong(name)
        }
    }

    private fun assertFieldsEqual(expected: Map<String, Any>, actual: Map<String, Any>, name: String) {
        assertEquals(name, expected.keys, actual.keys)
        for ((k, v) in expected) {
            val a = actual.getValue(k)
            if (v is ByteArray) assertArrayEquals("$name.$k", v, a as ByteArray) else assertEquals("$name.$k", v, a)
        }
    }

    @Test
    fun validVectorsDecodeAndReencodeExactly() {
        val valid = vectors.getJSONArray("valid")
        assertEquals(6, valid.length())
        for (i in 0 until valid.length()) {
            val v = valid.getJSONObject(i)
            val name = v.getString("name")
            val bytes = v.getString("hex").hexToBytes()
            val msg = Codec.decode(bytes)
            assertEquals(name, MsgType.valueOf(v.getString("type")), msg.type)
            val expected = fields(v.getJSONObject("fields"))
            assertFieldsEqual(expected, msg.fields, name)
            assertEquals(name, v.getString("hex"), Codec.encode(msg.type, expected).toHex())
        }
    }

    @Test
    fun vectorSignaturesVerify() {
        val valid = vectors.getJSONArray("valid")
        for (i in 0 until valid.length()) {
            val v = valid.getJSONObject(i)
            if (!v.has("signature")) continue
            val s = v.getJSONObject("signature")
            val msg = Codec.decode(v.getString("hex").hexToBytes())
            assertEquals(s.getString("signed_hex"), msg.signedPart!!.toHex())
            val key = SignatureVerifier.publicKeyFromSpki(s.getString("public_key").hexToBytes())
            assertTrue(v.getString("name"),
                SignatureVerifier.verify(key, labels.getValue(s.getString("label")) + msg.signedPart!!, msg.bytes("signature")))
        }
    }

    @Test
    fun invalidSignatureVectorsFail() {
        val bad = vectors.getJSONArray("signatures_invalid")
        for (i in 0 until bad.length()) {
            val v = bad.getJSONObject(i)
            val key = SignatureVerifier.publicKeyFromSpki(v.getString("public_key").hexToBytes())
            val signed = labels.getValue(v.getString("label")) + v.getString("signed_hex").hexToBytes()
            assertFalse(v.getString("name"), SignatureVerifier.verify(key, signed, v.getString("signature_hex").hexToBytes()))
        }
    }

    @Test
    fun invalidVectorsRejectedWithExpectedError() {
        val invalid = vectors.getJSONArray("invalid")
        for (i in 0 until invalid.length()) {
            val v = invalid.getJSONObject(i)
            try {
                Codec.decode(v.getString("hex").hexToBytes())
                fail("${v.getString("name")}: accepted")
            } catch (e: ProtocolException) {
                assertEquals(v.getString("name"), ErrorCode.valueOf(v.getString("error")), e.error)
            }
        }
    }

    @Test
    fun encodeRefusesInvalidFields() {
        val cases = listOf<Pair<MsgType, Map<String, Any>>>(
            MsgType.STATUS to emptyMap(),
            MsgType.STATUS to mapOf("status" to 1, "challenge" to ByteArray(32)),
            MsgType.STATUS to mapOf("status" to 256),
            MsgType.ERROR to mapOf("error_code" to 1, "error_detail" to "a‮b"),
        )
        for ((type, f) in cases) {
            try {
                Codec.encode(type, f)
                fail("accepted $f")
            } catch (e: ProtocolException) {
                assertEquals(ErrorCode.MALFORMED, e.error)
            }
        }
    }
}
