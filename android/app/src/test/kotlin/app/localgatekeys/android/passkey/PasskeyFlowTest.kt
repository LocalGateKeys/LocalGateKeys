package app.localgatekeys.android.passkey

import app.localgatekeys.android.autofill.testRules
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.sync.StoreSnapshot
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.security.Signature

private fun vectors(name: String): List<Map<String, JsonValue>> {
    val f = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"), "tests/vectors/sync/passkeys/$name")
    return (CanonicalJson.parse(f.readBytes()) as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }
}

private fun Map<String, JsonValue>.s(k: String): String = (getValue(k) as JsonValue.Str).v

private fun reason(block: () -> Unit): WebAuthnException.Reason {
    try {
        block()
    } catch (e: WebAuthnException) {
        return e.reason
    }
    fail("expected WebAuthnException")
    error("unreachable")
}

/** Gives [first] for the first request, then counting bytes. */
private class ScriptedRandom(private val first: ByteArray) : RandomSource {
    private var used = false
    private var n = 0
    override fun bytes(count: Int): ByteArray {
        if (!used && count == first.size) {
            used = true
            return first.copyOf()
        }
        return ByteArray(count) { (n++ and 0xff).toByte() }
    }
}

class ClientDataTest {
    @Test
    fun client_data_json_member_order_and_escaping() {
        val json = ClientData.json(ClientData.GET, byteArrayOf(1, 2, 3, (-1).toByte()), "https://example.com").toString(Charsets.UTF_8)
        assertEquals("""{"type":"webauthn.get","challenge":"AQID_w","origin":"https://example.com","crossOrigin":false}""", json)
        val app = ClientData.json(ClientData.CREATE, byteArrayOf(0), "android:apk-key-hash:abc", "com.example").toString(Charsets.UTF_8)
        assertEquals("""{"type":"webauthn.create","challenge":"AA","origin":"android:apk-key-hash:abc","crossOrigin":false,"androidPackageName":"com.example"}""", app)
        assertEquals("\"a\\\"b\\\\c\\u000a\"", ClientData.quote("a\"b\\c\n"))
    }

    @Test
    fun hash_is_sha256() {
        val j = ClientData.json(ClientData.GET, byteArrayOf(9), "https://a.example")
        assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(j), ClientData.hash(j))
    }

    @Test
    fun apk_key_hash_origin() {
        val cert = ByteArray(32) { it.toByte() }
        assertEquals("android:apk-key-hash:" + Base64Url.encodeNoPad(cert), ClientData.apkKeyHashOrigin(cert))
        assertFalse(ClientData.apkKeyHashOrigin(cert).contains("="))
    }
}

class WebAuthnRequestTest {
    private val create = """
        {"rp":{"id":"webauthn.io","name":"WebAuthn.io"},
         "user":{"id":"dXNlci0x","name":"sample","displayName":"Sample User"},
         "challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}],
         "excludeCredentials":[{"type":"public-key","id":"AQID"}],"timeout":60000,
         "authenticatorSelection":{"residentKey":"required","userVerification":"preferred"},"attestation":"none"}
    """.trimIndent()

    @Test
    fun parses_creation_options() {
        val r = CreationRequest.parse(create)
        assertEquals("webauthn.io", r.rpId)
        assertEquals("WebAuthn.io", r.rpName)
        assertArrayEquals("user-1".toByteArray(), r.userHandle)
        assertEquals("sample", r.userName)
        assertEquals("Sample User", r.userDisplayName)
        assertArrayEquals("challenge".toByteArray(), r.challenge)
        assertEquals(1, r.exclude.size)
        assertFalse(r.toString().contains("sample"))
    }

    @Test
    fun refuses_without_es256_or_malformed() {
        assertEquals(WebAuthnException.Reason.NO_ES256, reason { CreationRequest.parse(create.replace("\"alg\":-7", "\"alg\":-257")) })
        assertEquals(WebAuthnException.Reason.MALFORMED, reason { CreationRequest.parse("{}") })
        assertEquals(WebAuthnException.Reason.MALFORMED, reason { CreationRequest.parse("not json") })
        assertEquals(WebAuthnException.Reason.MALFORMED, reason { CreationRequest.parse(create.replace("\"dXNlci0x\"", "\"\"")) })
    }

    @Test
    fun empty_params_mean_defaults() {
        assertEquals("webauthn.io", CreationRequest.parse(create.replace(Regex("\"pubKeyCredParams\":\\[[^]]*]"), "\"pubKeyCredParams\":[]")).rpId)
    }

    @Test
    fun parses_request_options() {
        val r = AssertionRequest.parse("""{"challenge":"AAEC","rpId":"example.com","allowCredentials":[{"type":"public-key","id":"BAUG"},{"type":"other","id":"BwgJ"}],"userVerification":"required"}""")
        assertEquals("example.com", r.rpId)
        assertArrayEquals(byteArrayOf(0, 1, 2), r.challenge)
        assertEquals(1, r.allowed.size)
        assertArrayEquals(byteArrayOf(4, 5, 6), r.allowed[0])
        assertNull(AssertionRequest.parse("""{"challenge":"AAEC"}""").rpId)
        assertEquals(WebAuthnException.Reason.MALFORMED, reason { AssertionRequest.parse("""{"rpId":"x"}""") })
    }
}

class CallerOriginTest {
    private val chrome = ByteArray(32) { 7 }
    private val appCert = ByteArray(32) { 9 }
    private val privileged = PrivilegedBrowsers.parse(
        """{"apps":[{"type":"android","info":{"package_name":"com.android.chrome","signatures":[{"build":"release","cert_fingerprint_sha256":"${"07:".repeat(31)}07"}]}},
            {"type":"other","info":{"package_name":"com.x"}}]}""",
    )
    private val origin = CallerOrigin(privileged, testRules)

    @Test
    fun allowlist_needs_package_and_certificate() {
        assertTrue(privileged.trusts("com.android.chrome", listOf(chrome)))
        assertFalse(privileged.trusts("com.android.chrome", listOf(appCert)))
        assertFalse(privileged.trusts("com.evil", listOf(chrome)))
        assertEquals(setOf("com.android.chrome"), privileged.packages)
        assertTrue(PrivilegedBrowsers.parse("garbage").packages.isEmpty())
        assertNull(PrivilegedBrowsers.fingerprint("AB:CD"))
    }

    @Test
    fun privileged_browser_origin_and_hash_are_used() {
        val hash = ByteArray(32) { 3 }
        val v = origin.verify("com.android.chrome", listOf(chrome), "https://login.example.com", "example.com", hash)
        assertEquals("https://login.example.com", v.origin)
        assertEquals("example.com", v.rpId)
        assertArrayEquals(hash, v.clientDataHash)
        assertNull(v.androidPackage)
        assertEquals("login.example.com", origin.verify("com.android.chrome", listOf(chrome), "https://login.example.com/", null, null).rpId)
    }

    @Test
    fun rp_id_must_be_origin_host_or_registrable_parent() {
        fun r(rp: String, o: String = "https://login.example.co.uk") =
            reason { origin.verify("com.android.chrome", listOf(chrome), o, rp, null) }
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, r("co.uk"))
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, r("other.co.uk"))
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, r("evil-example.co.uk"))
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, r("deeper.login.example.co.uk"))
        assertEquals(WebAuthnException.Reason.ORIGIN_REFUSED, r("example.com", "http://example.com"))
        assertEquals("example.co.uk", origin.verify("com.android.chrome", listOf(chrome), "https://login.example.co.uk", "example.co.uk", null).rpId)
        assertEquals("localhost", origin.verify("com.android.chrome", listOf(chrome), "http://localhost:8080", "localhost", null).rpId)
    }

    @Test
    fun apps_get_apk_key_hash_and_their_hash_is_ignored() {
        val v = origin.verify("com.example.app", listOf(appCert), "https://example.com", "example.com", ByteArray(32))
        assertEquals(ClientData.apkKeyHashOrigin(appCert), v.origin)
        assertNull(v.clientDataHash)
        assertEquals("com.example.app", v.androidPackage)
        // A look-alike Chrome (wrong certificate) is an app too.
        assertEquals(ClientData.apkKeyHashOrigin(appCert), origin.verify("com.android.chrome", listOf(appCert), "https://example.com", "example.com", null).origin)
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, reason { origin.verify("com.example.app", listOf(appCert), null, null, null) })
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, reason { origin.verify("com.example.app", listOf(appCert), null, "com", null) })
        assertEquals(WebAuthnException.Reason.RP_ID_REFUSED, reason { origin.verify("com.example.app", listOf(appCert), null, "10.0.0.1", null) })
        assertEquals(WebAuthnException.Reason.ORIGIN_REFUSED, reason { origin.verify("com.example.app", emptyList(), null, "example.com", null) })
    }

    @Test
    fun no_suffix_list_fails_closed() {
        val closed = CallerOrigin(privileged, null)
        assertFalse(closed.rpIdAllowed("example.com", null))
        assertTrue(closed.rpIdAllowed("example.com", "example.com"))
    }
}

class PasskeyVaultTest {
    private fun passkeySnapshot(rpId: String, key: PasskeyKey, credentialId: ByteArray, id: String = "p1", deleted: Boolean = false): StoreSnapshot {
        val made = PasskeyRecord.newPayload(rpId, "RP", "sample", "Sample", byteArrayOf(5, 6), credentialId, key, "2026-10-29")
        val rec = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(id), "kind" to JsonValue.Str("passkey"), "title" to JsonValue.Str(made.title),
                "payload" to made.fields, "tags" to JsonValue.Arr(emptyList()), "updated_at" to JsonValue.Int(1),
            ),
        )
        return snapshot(listOf(rec), deleted = if (deleted) setOf(id) else emptySet())
    }

    @Test
    fun assertion_matches_vectors_and_verifies() {
        for (v in vectors("assertion.json")) {
            val key = PasskeyKey.fromPkcs8B64Url(v.s("private_key_b64u"))!!
            val cred = byteArrayOf(1, 2, 3, 4)
            val rp = v.s("rp_id")
            val s = passkeySnapshot(rp.uppercase(), key, cred)
            assertEquals(1, PasskeyVault.candidates(s, rp.uppercase(), emptyList()).size)
            val hash = Hex.decode(v.s("client_data_hash_hex"))
            val uv = v.getValue("user_verified") == JsonValue.Bool(true)
            val a = PasskeyVault.assert(s, "p1", rp, hash, uv)
            assertEquals(v.s("authenticator_data_hex"), Hex.lower(a.authenticatorData))
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(key.publicKey)
            sig.update(a.authenticatorData + hash)
            assertTrue(sig.verify(a.signature))
            assertArrayEquals(cred, a.credentialId)
            assertArrayEquals(byteArrayOf(5, 6), a.userHandle)
        }
    }

    @Test
    fun candidates_exact_rp_allow_list_and_tombstones() {
        val key = PasskeyKey.generate()
        val s = passkeySnapshot("example.com", key, byteArrayOf(1))
        assertTrue(PasskeyVault.candidates(s, "login.example.com", emptyList()).isEmpty())
        assertTrue(PasskeyVault.candidates(s, "com", emptyList()).isEmpty())
        assertEquals(1, PasskeyVault.candidates(s, "example.com", listOf(byteArrayOf(1))).size)
        assertTrue(PasskeyVault.candidates(s, "example.com", listOf(byteArrayOf(2))).isEmpty())
        assertTrue(PasskeyVault.candidates(passkeySnapshot("example.com", key, byteArrayOf(1), deleted = true), "example.com", emptyList()).isEmpty())
        assertEquals(WebAuthnException.Reason.NOT_FOUND, reason { PasskeyVault.assert(s, "p1", "other.com", ByteArray(32), true) })
        assertEquals(WebAuthnException.Reason.NOT_FOUND, reason { PasskeyVault.assert(s, "nope", "example.com", ByteArray(32), true) })
    }

    @Test
    fun assertion_never_writes() {
        val store = CountingStore(passkeySnapshot("example.com", PasskeyKey.generate(), byteArrayOf(1)))
        PasskeyVault.assert(store.load(), "p1", "example.com", ByteArray(32), true)
        assertEquals(0, store.commits)
    }

    @Test
    fun registration_matches_vectors() {
        for (v in vectors("registration.json")) {
            val key = PasskeyKey.fromPkcs8B64Url(v.s("private_key_b64u"))!!
            val cred = Hex.decode(v.s("credential_id_hex"))
            val store = CountingStore(snapshot(emptyList()))
            val reg = PasskeyVault.register(
                store, v.s("rp_id"), "RP", "sample", "Sample", byteArrayOf(1), emptyList(), 1_800_000_000, "2026-10-29",
                ScriptedRandom(cred), isPro = { false }, newKey = { key },
            )
            assertEquals(v.s("attestation_object_hex"), Hex.lower(reg.attestationObject))
            assertEquals(v.s("authenticator_data_hex"), Hex.lower(reg.authenticatorData))
            assertArrayEquals(cred, reg.credentialId)
            assertArrayEquals(key.publicKey.encoded, reg.spki)
            assertEquals(1, store.commits)
            val stored = PasskeyRecord.from(store.load().records.getValue(reg.itemId), reg.itemId)!!
            assertEquals(key, stored.key)
            assertArrayEquals(cred, stored.credentialId)
        }
    }

    @Test
    fun registration_limit_and_exclude() {
        val key = PasskeyKey.generate()
        val full = snapshot(
            (1..ItemLimit.FREE_ITEMS).map { n ->
                JsonValue.Obj(mapOf("id" to JsonValue.Str("n$n"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("t"),
                    "payload" to JsonValue.Obj(mapOf("body" to JsonValue.Str("b"))), "tags" to JsonValue.Arr(emptyList()), "updated_at" to JsonValue.Int(1)))
            },
        )
        fun reg(store: CountingStore, pro: Boolean, exclude: List<ByteArray> = emptyList()) = PasskeyVault.register(
            store, "example.com", "", "u", "", byteArrayOf(1), exclude, 1, "2026-10-29", ScriptedRandom(ByteArray(16) { 4 }), isPro = { pro },
        )
        var made = 0
        val blocked = CountingStore(full)
        assertEquals(WebAuthnException.Reason.NEEDS_PRO, reason { reg(blocked, false); made++ })
        assertEquals(0, blocked.commits)
        assertNotNull(reg(CountingStore(full), true))
        val existing = CountingStore(passkeySnapshot("example.com", key, byteArrayOf(1)))
        assertEquals(WebAuthnException.Reason.EXCLUDED, reason { reg(existing, true, listOf(byteArrayOf(1))) })
        assertNotNull(reg(existing, true, listOf(byteArrayOf(2))))
        assertEquals(0, made)
    }

    @Test
    fun response_json_shapes() {
        val reg = (CanonicalJson.parse(WebAuthnResponse.registration(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4), byteArrayOf(5)).toByteArray()) as JsonValue.Obj).fields
        assertEquals(JsonValue.Str("AQ"), reg["id"])
        assertEquals(JsonValue.Str("AQ"), reg["rawId"])
        assertEquals(JsonValue.Str("public-key"), reg["type"])
        val rr = (reg["response"] as JsonValue.Obj).fields
        assertEquals(JsonValue.Str("Aw"), rr["attestationObject"])
        assertEquals(JsonValue.Int(-7), rr["publicKeyAlgorithm"])
        val asr = (CanonicalJson.parse(WebAuthnResponse.assertion(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4), byteArrayOf(5)).toByteArray()) as JsonValue.Obj).fields
        val ar = (asr["response"] as JsonValue.Obj).fields
        assertEquals(setOf("clientDataJSON", "authenticatorData", "signature", "userHandle"), ar.keys)
        assertEquals(JsonValue.Str("BQ"), ar["userHandle"])
    }
}
