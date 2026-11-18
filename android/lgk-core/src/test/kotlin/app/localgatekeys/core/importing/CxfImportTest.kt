package app.localgatekeys.core.importing

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Credential Exchange (CXF) import: the Windows `tests/test_importer_cxf.py` cases (the review side is in the app tests). */
class CxfImportTest {
    private val sample: ByteArray = javaClass.getResource("/cxf/apple-passwords-sample.json")!!.readBytes()

    private fun doc(vararg items: String): ByteArray = """{"id": "QQ", "userName": "u", "items": [${items.joinToString(",")}]}""".toByteArray()

    @Test
    fun sample_counts() {
        val (records, skipped) = CxfImport.parse(sample)
        val kinds = records.map { it.kind }
        assertEquals(2, kinds.count { it == ImportCandidate.Kind.LOGIN })
        assertEquals(1, kinds.count { it == ImportCandidate.Kind.PASSKEY })
        assertEquals(0, kinds.count { it == ImportCandidate.Kind.NOTE })
        assertEquals(listOf("credit-card"), skipped)
        val mail = records.first { it.title == "Example Mail" }
        assertEquals(listOf("https://mail.example.test/login", "https://example.test"), mail.urls)
        assertEquals(Triple("ada", "correct horse", "recovery in drawer"), Triple(mail.username, mail.password, mail.notes))
        val p = records.first { it.kind == ImportCandidate.Kind.PASSKEY }.passkey
        assertEquals("pk.example.test", p["relying_party_id"])
        assertEquals("AQIDBAUGBwg", p["credential_id"])
        assertEquals("CgsMDQ4P", p["user_handle"])
        assertEquals("bob", p["user_name"])
        assertEquals("Bob B", p["user_display_name"])
        assertEquals("ES256", p["algorithm"])
        assertTrue(!p["private_key"].isNullOrEmpty())
        assertEquals(
            listOf(ImportCandidate.Kind.LOGIN, ImportCandidate.Kind.PASSKEY, ImportCandidate.Kind.LOGIN), kinds,
            "in item order, an item's passkeys before its login (as on Windows)",
        )
    }

    @Test
    fun totp_merges_into_login() {
        val mail = CxfImport.parse(sample).first.first { it.title == "Example Mail" }
        assertTrue(mail.totp.startsWith("otpauth://totp/"))
        assertTrue("secret=JBSWY3DPEHPK3PXP" in mail.totp)
        assertTrue("issuer=Example" in mail.totp)
    }

    @Test
    fun orphan_totp_becomes_login() {
        val (records, skipped) = CxfImport.parse(
            doc("""{"id": "a", "title": "Codes", "scope": {"urls": ["https://c.test"]}, "credentials": [{"type": "totp", "secret": "JBSWY3DPEHPK3PXP"}]}"""),
        )
        assertEquals(emptyList(), skipped)
        val record = records.single()
        assertEquals(ImportCandidate.Kind.LOGIN, record.kind)
        assertEquals("" to "", record.username to record.password)
        assertEquals(listOf("https://c.test"), record.urls)
        assertTrue("secret=JBSWY3DPEHPK3PXP" in record.totp)
    }

    @Test
    fun orphan_note_becomes_note() {
        val (records, _) = CxfImport.parse(doc("""{"id": "a", "title": "Memo", "credentials": [{"type": "note", "content": {"value": "hello"}}]}"""))
        assertEquals(listOf(Triple(ImportCandidate.Kind.NOTE, "Memo", "hello")), records.map { Triple(it.kind, it.title, it.notes) })
    }

    @Test
    fun unknown_type_skipped_and_named() {
        val (records, skipped) = CxfImport.parse(
            doc("""{"id": "a", "title": "X", "credentials": [{"type": "ssh-key", "privateKey": "x"}, {"type": "wifi"}, {"type": "ssh-key"}, {"notype": 1}]}"""),
        )
        assertEquals(emptyList(), records)
        assertEquals(listOf("ssh-key", "wifi", "ssh-key", "unknown"), skipped)
        val result = CxfImport.candidates(doc("""{"id": "a", "title": "X", "credentials": [{"type": "ssh-key"}]}"""))
        val line = result.skipped.single()
        assertTrue("ssh-key" in line.message)
        assertEquals(CxfImport.SKIPPED_TYPES, line.code)
        assertEquals(listOf("1", "ssh-key (1)"), line.args)
    }

    @Test
    fun unknown_passkey_field_ignored() {
        val text = String(sample, Charsets.UTF_8)
            .replace("\"type\": \"passkey\",", "\"type\": \"passkey\", \"fido2Extensions\": {\"hmacCredentials\": {\"algorithm\": \"x\"}}, \"futureField\": 42,")
            .replace("{\"type\": \"basic-auth\", \"username\": {\"value\": \"bob\"}", "{\"type\": \"basic-auth\", \"extra\": \"ignored\", \"username\": {\"value\": \"bob\"}")
        assertTrue("futureField" in text && "\"extra\"" in text)
        val (records, skipped) = CxfImport.parse(text.toByteArray())
        assertEquals(1, records.count { it.kind == ImportCandidate.Kind.PASSKEY })
        assertEquals(listOf("credit-card"), skipped)
    }

    @Test
    fun bad_passkey_is_skipped_not_fatal() {
        val (records, skipped) = CxfImport.parse(
            doc("""{"id": "a", "title": "P", "credentials": [{"type": "passkey", "credentialId": "!!", "rpId": "x.test", "key": "zz"}]}"""),
        )
        assertEquals(emptyList(), records)
        assertEquals(listOf("passkey"), skipped)
    }

    @Test
    fun passkey_with_a_key_that_is_not_pkcs8_is_skipped() {
        val (records, skipped) = CxfImport.parse(
            doc("""{"id": "a", "title": "P", "credentials": [{"type": "passkey", "credentialId": "AQID", "rpId": "x.test", "key": "AAECAwQFBgcICQ"}]}"""),
        )
        assertEquals(emptyList(), records)
        assertEquals(listOf("passkey"), skipped)
    }

    @Test
    fun key_algorithm_is_read_from_the_pkcs8_key() {
        fun der(alg: String, spec: java.security.spec.AlgorithmParameterSpec? = null, bits: Int = 0): ByteArray {
            val gen = java.security.KeyPairGenerator.getInstance(alg)
            if (spec != null) gen.initialize(spec) else if (bits > 0) gen.initialize(bits)
            return gen.generateKeyPair().private.encoded
        }
        assertEquals("ES256", CxfImport.algorithm(der("EC", java.security.spec.ECGenParameterSpec("secp256r1"))))
        assertEquals("ES384", CxfImport.algorithm(der("EC", java.security.spec.ECGenParameterSpec("secp384r1"))))
        assertEquals("EdDSA", CxfImport.algorithm(der("Ed25519")))
        assertEquals("RS256", CxfImport.algorithm(der("RSA", bits = 2048)))
        assertEquals(null, CxfImport.algorithm(der("EC", java.security.spec.ECGenParameterSpec("secp256r1")) + byteArrayOf(0)))
        assertEquals(null, CxfImport.algorithm(byteArrayOf(0x30, 0x00)))
    }

    @Test
    fun detect_returns_cxf() {
        assertEquals(ImportFormat.CXF, ImportFormat.fromRaw("cxf"))
        assertTrue(ImportFormat.CXF.supported)
        assertEquals(ImportFormat.CXF, ImportDetect.detect(sample, "export.json"))
        assertEquals(ImportFormat.CXF, ImportDetect.detect(sample, "export.cxf"))
        val result = ImportSource.candidates(sample, ImportFormat.CXF)
        assertEquals(3, result.candidates.size)
    }

    @Test
    fun bitwarden_json_still_detected() {
        val blob = """{"encrypted": false, "items": [{"type": 1, "name": "x", "login": {}}]}""".toByteArray()
        assertEquals(ImportFormat.BITWARDEN, ImportDetect.detect(blob, "x.json"))
    }

    @Test
    fun malformed_input_raises_format_error_or_empty() {
        for (blob in listOf("", "[]", "{}", """{"items": 5}""", "{not json", """{"items": [1, "x", null]}""", "ÿþ{")) {
            val records = try {
                CxfImport.parse(blob.toByteArray(Charsets.ISO_8859_1)).first
            } catch (e: ImportException) {
                continue
            }
            assertEquals(emptyList(), records, blob)
        }
    }

    @Test
    fun oversized_file_rejected() {
        val e = assertFailsWith<ImportException> { CxfImport.parse(("{" + " ".repeat(17 * 1024 * 1024) + "}").toByteArray()) }
        assertEquals(ImportException.Kind.TOO_LARGE, e.kind)
    }

    @Test
    fun a_20_mb_cxf_file_is_named_and_refused_as_too_large() {
        val item = """{"id": "a", "title": "T", "scope": {"urls": ["https://t.test"]}, "credentials": [{"type": "basic-auth", "username": "u", "password": "p"}]}"""
        val body = StringBuilder("{\"items\": [")
        while (body.length < 20 * 1024 * 1024) body.append(item).append(',')
        body.append(item).append("]}")
        val bytes = body.toString().toByteArray()
        assertTrue(bytes.size > 20 * 1024 * 1024)
        assertEquals(ImportFormat.CXF, ImportDetect.detect(bytes, "big.json"))
        val e = assertFailsWith<ImportException> { ImportSource.candidates(bytes, ImportFormat.CXF) }
        assertEquals(ImportException.Kind.TOO_LARGE, e.kind)
    }

    @Test
    fun too_many_items_is_refused() {
        val item = """{"id": "a", "title": "T", "scope": {"urls": ["https://t.test"]}, "credentials": [{"type": "basic-auth", "username": "u", "password": "p"}]}"""
        val e = assertFailsWith<ImportException> { CxfImport.parse(doc(*Array(ImportSource.MAX_RECORDS + 1) { item })) }
        assertEquals(ImportException.Kind.TOO_MANY_ROWS, e.kind)
    }

    @Test
    fun second_basic_auth_is_skipped_like_swift() {
        val (records, skipped) = CxfImport.parse(
            doc(
                """{"id": "a", "title": "Two", "scope": {"urls": ["https://two.test"]}, "credentials": [""" +
                    """{"type": "basic-auth", "username": "a", "password": "p1"}, {"type": "basic-auth", "username": "b", "password": "p2"}]}""",
            ),
        )
        assertEquals(listOf(ImportCandidate.Kind.LOGIN to "a"), records.map { it.kind to it.username })
        assertEquals(listOf("basic-auth"), skipped)
    }

    @Test
    fun candidates_never_print_values() {
        val shown = CxfImport.parse(sample).first.joinToString { it.toString() }
        assertTrue("correct horse" !in shown && "MIGHAg" !in shown)
    }

    @Test
    fun broken_unicode_escape_is_mended_not_fatal() {
        val (records, skipped) = CxfImport.parse(
            doc(
                """{"id": "a", "title": "Codes", "scope": {"urls": ["https://c.test"]}, "credentials": [""" +
                    """{"type": "basic-auth", "username": "ann", "password": "pw\ud800"},""" +
                    """{"type": "totp", "secret": "JBSWY3DPEHPK3PXP", "issuer": "Bad\ud800"}]}""",
                """{"id": "b", "title": "Fine", "credentials": [{"type": "note", "content": "kept"}]}""",
            ),
        )
        assertEquals(emptyList(), skipped)
        assertEquals(listOf(ImportCandidate.Kind.LOGIN to "Codes", ImportCandidate.Kind.NOTE to "Fine"), records.map { it.kind to it.title })
        assertEquals("ann" to "pw\uFFFD", records[0].username to records[0].password)
        assertTrue("secret=JBSWY3DPEHPK3PXP" in records[0].totp && "issuer=Bad%EF%BF%BD" in records[0].totp)
    }
}
