package dev.phonekey.authenticator.protocol

import dev.phonekey.authenticator.crypto.SignatureVerifier
import dev.phonekey.authenticator.store.hexToBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Phone-side request validation (PROTOCOL.md §8.2; SECURITY.md T-6, T-9) with software
 * keys standing in for the laptop and the Keystore key.
 */
class AuthenticatorCoreTest {
    private val verifierKey = newKey()
    private val deviceKey = newKey()
    private val verifierSpki = verifierKey.public.encoded
    private val verifierId = AuthenticatorCore.sha256(verifierSpki)
    private val deviceId = AuthenticatorCore.sha256(deviceKey.public.encoded)
    private val record = VerifierRecord(verifierId, verifierSpki, "laptop", "alice", "alias", deviceId, "80:91:33:53:2C:C8")

    private fun newKey(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun sign(key: KeyPair, label: ByteArray, data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(key.private); update(label); update(data); sign() }

    private fun authRequest(
        signer: KeyPair = verifierKey,
        verifier: ByteArray = verifierId,
        device: ByteArray = deviceId,
        account: String = "alice",
    ): ByteArray {
        val unsigned = Codec.encodeUnsigned(MsgType.AUTH_REQUEST, mapOf(
            "verifier_id" to verifier, "device_id" to device, "request_id" to ByteArray(16) { 7 },
            "challenge" to ByteArray(32) { 1 }, "action" to "linux.sudo", "resource" to "laptop",
            "account" to account, "issued_at" to 0L, "ttl_ms" to 30_000L,
        ))
        return Codec.withSignature(unsigned, sign(signer, Labels.AUTH_REQUEST, unsigned))
    }

    private fun evaluate(data: ByteArray) =
        AuthenticatorCore.evaluateAuthRequest(data) { id -> record.takeIf { id.contentEquals(verifierId) } }

    private fun errorOf(decision: AuthDecision): ErrorCode {
        assertTrue("expected Reply, got $decision", decision is AuthDecision.Reply)
        return ErrorCode.of(Codec.decode((decision as AuthDecision.Reply).message).long("error_code").toInt())!!
    }

    @Test
    fun validRequestPromptsAndResponseBindsRequestHash() {
        val request = authRequest()
        val decision = evaluate(request) as AuthDecision.Prompt
        assertEquals("linux.sudo", decision.action)
        assertEquals("laptop", decision.resource)
        assertEquals(30_000L, decision.ttlMs)

        val response = Codec.withSignature(decision.unsignedResponse,
            sign(deviceKey, Labels.AUTH_ASSERTION, decision.unsignedResponse))
        val msg = Codec.decode(response)
        assertArrayEquals(AuthenticatorCore.sha256(request), msg.bytes("request_hash"))
        assertTrue(SignatureVerifier.verify(SignatureVerifier.publicKeyFromSpki(deviceKey.public.encoded),
            Labels.AUTH_ASSERTION + msg.signedPart!!, msg.bytes("signature")))
    }

    @Test
    fun unknownVerifierIsRefusedWithoutPrompt() {
        val stranger = newKey()
        val request = authRequest(signer = stranger, verifier = AuthenticatorCore.sha256(stranger.public.encoded))
        assertEquals(ErrorCode.UNKNOWN_VERIFIER, errorOf(evaluate(request)))
    }

    @Test
    fun forgedVerifierSignatureIsRefused() {
        assertEquals(ErrorCode.BAD_SIGNATURE, errorOf(evaluate(authRequest(signer = newKey()))))
    }

    @Test
    fun tamperedRequestIsRefused() {
        val request = authRequest()
        val tampered = request.copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
        assertTrue(evaluate(tampered) is AuthDecision.Reply)
    }

    @Test
    fun requestForAnotherDeviceIsIgnoredSilently() {
        assertSame(AuthDecision.Ignore, evaluate(authRequest(device = ByteArray(32))))
    }

    @Test
    fun accountMismatchIsRefused() {
        assertEquals(ErrorCode.UNKNOWN_DEVICE, errorOf(evaluate(authRequest(account = "root"))))
    }

    @Test
    fun malformedAndWrongTypeAreRefused() {
        assertEquals(ErrorCode.MALFORMED, errorOf(evaluate(byteArrayOf(1, 2, 3))))
        assertEquals(ErrorCode.MALFORMED, errorOf(evaluate(AuthenticatorCore.status(StatusCode.READY))))
    }

    @Test
    fun pairRequestWithValidSelfSignatureIsAccepted() {
        val offer = AuthenticatorCore.parsePairRequest(pairRequest(verifierKey))
        assertArrayEquals(verifierId, offer.verifierId)
        assertEquals("alice", offer.account)

        val unsigned = AuthenticatorCore.unsignedPairResponse(offer, deviceKey.public.encoded, "Pixel", 2,
            listOf(ByteArray(10), ByteArray(20)))
        val msg = Codec.decode(Codec.withSignature(unsigned, sign(deviceKey, Labels.PAIR_RESPONSE, unsigned)))
        assertArrayEquals(offer.requestHash, msg.bytes("request_hash"))
        assertArrayEquals(deviceId, msg.bytes("device_id"))
        assertEquals(2 + 10 + 2 + 20, msg.bytes("attestation_chain").size)
    }

    @Test
    fun pairRequestWithoutProofOfPossessionIsRejected() {
        try {
            AuthenticatorCore.parsePairRequest(pairRequest(signer = newKey(), claimed = verifierKey))
            fail("accepted")
        } catch (e: ProtocolException) {
            assertEquals(ErrorCode.BAD_SIGNATURE, e.error)
        }
    }

    @Test
    fun pythonGeneratedPairRequestVectorIsAccepted() {
        val json = org.json.JSONObject(javaClass.classLoader!!.getResourceAsStream("v1.json")!!.bufferedReader().readText())
        val valid = json.getJSONArray("valid")
        val vector = (0 until valid.length()).map { valid.getJSONObject(it) }.first { it.getString("name") == "pair_request" }
        val offer = AuthenticatorCore.parsePairRequest(vector.getString("hex").hexToBytes())
        assertEquals("alice", offer.account)
    }

    @Test
    fun oversizedAttestationIsOmitted() {
        assertEquals(null, AuthenticatorCore.encodeAttestation(listOf(ByteArray(13_000))))
        assertEquals(null, AuthenticatorCore.encodeAttestation(null))
    }

    @Test
    fun namesAreSanitized() {
        assertEquals("evilname", AuthenticatorCore.sanitizeName("evil‮name\n"))
        assertEquals("Android phone", AuthenticatorCore.sanitizeName("\u0000"))
        assertTrue(AuthenticatorCore.sanitizeName("é".repeat(100)).toByteArray().size <= 64)
    }

    private fun pairRequest(signer: KeyPair, claimed: KeyPair = signer): ByteArray {
        val spki = claimed.public.encoded
        val unsigned = Codec.encodeUnsigned(MsgType.PAIR_REQUEST, mapOf(
            "verifier_id" to AuthenticatorCore.sha256(spki), "action" to "phonekey.pair", "account" to "alice",
            "issued_at" to 0L, "ttl_ms" to 120_000L, "public_key" to spki, "display_name" to "laptop",
            "pairing_nonce" to ByteArray(32) { 3 },
        ))
        return Codec.withSignature(unsigned, sign(signer, Labels.PAIR_REQUEST, unsigned))
    }
}
