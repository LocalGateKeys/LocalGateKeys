package app.localgatekeys.core.crypto

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.QueueRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The shared composite-key vectors (tests/vectors/composite_key, copied to test resources and checked byte for byte
 * by tests/test_vector_copies.py): key files, factor checks, the wrapping key and `app-password.bin` v2
 * (docs/formats/COMPOSITE_KEY_V1.md §1-§4, §7).
 */
class CompositeKeyTest {
    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/composite_key/$name")?.use { it.readBytes() } ?: error("missing resource $name")

    private val root = CanonicalJson.parse(resource("cases.json")).obj().fields
    private fun hex(v: JsonValue?): ByteArray = Hex.decode(v!!.str())
    private val argon = root.getValue("argon").obj().fields
    private val argonOut = hex(argon["output_hex"])
    private val cases = root.getValue("cases").arr().associateBy { it.obj().fields.getValue("name").str() }
    private fun case(name: String) = cases.getValue(name).obj().fields
    private fun specs(v: JsonValue?): List<FactorSpec> = v!!.arr().map { FactorSpec.fromJson(it) }
    private val keyFiles = root.getValue("keyfiles").arr().associate {
        val f = it.obj().fields
        f.getValue("name").str() to f
    }
    private val yubikey = root.getValue("yubikey").obj().fields

    /** Counts Argon2id runs (a factor mismatch must fail before any). */
    private class CountingArgon : Argon2id {
        var calls = 0
        override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray {
            calls++
            return BouncyCastleArgon2id().derive(password, salt, memoryKiB, iterations, parallelism, length)
        }
    }

    @Test fun vectors() {
        val password = argon.getValue("password").str().toByteArray(Charsets.UTF_8)
        assertContentEquals(
            argonOut,
            BouncyCastleArgon2id().derive(password, hex(argon["salt_hex"]), argon.getValue("memory_cost_kib").long().toInt(), 1, 1, 32),
        )
        assertEquals("localgatekeys|composite|v1", root.getValue("composite_salt").str())
        assertEquals("localgatekeys|factor-check|v1", root.getValue("check_info").str())
        val dataKey = hex(root["data_key_hex"])
        val generic = listOf(
            "no_factors", "keyfile_xml_v2", "keyfile_xml_v1", "keyfile_raw32", "keyfile_hex64", "keyfile_arbitrary",
            "yubikey_only", "keyfile_and_yubikey",
        )
        for (name in generic) {
            val c = case(name)
            val list = specs(c["factors"])
            val secrets = c.getValue("secrets_hex").arr().map { Hex.decode(it.str()) }
            if (list.isEmpty()) {
                assertTrue(c["info"] is JsonValue.Null)
                assertSame(argonOut, CompositeKey.combine(argonOut, list, secrets), "no factors: the Argon2id output itself")
            } else {
                assertEquals(c.getValue("info").str(), String(CompositeKey.info(list), Charsets.US_ASCII), "info $name")
                CompositeKey.verify(list, secrets)
                list.zip(secrets).forEach { (spec, secret) -> assertEquals(spec.check, CompositeKey.check(secret), "check $name") }
            }
            val key = CompositeKey.combine(argonOut, list, secrets)
            assertEquals(c.getValue("combine_hex").str(), Hex.lower(key), "combine $name")
            val w = c.getValue("wrap").obj().fields
            assertContentEquals(dataKey, CryptoBox.openGcm(key, hex(w["nonce_hex"]), hex(w["ciphertext_hex"]), hex(w["aad_hex"])), "wrap $name")
        }
        for ((name, f) in keyFiles) {
            val key = KeyFile.keyFromBytes(resource(f.getValue("file").str()))
            assertEquals(f.getValue("key_hex").str(), Hex.lower(key), "key file $name")
            assertEquals(f.getValue("check").str(), CompositeKey.check(key), "key file check $name")
        }
        for (r in root.getValue("keyfile_rejects").arr()) {
            val f = r.obj().fields
            assertFailsWith<KeyFileException>(f.getValue("name").str()) { KeyFile.keyFromBytes(resource(f.getValue("file").str())) }
        }
        assertEquals(yubikey.getValue("secret_hex").str(), Hex.lower(CompositeKey.yubikeySecret(hex(yubikey["response_hex"]))))
        assertEquals(yubikey.getValue("check").str(), CompositeKey.check(hex(yubikey["secret_hex"])))
        assertEquals(yubikey.getValue("padded_challenge_hex").str(), Hex.lower(CompositeKey.padChallenge(hex(yubikey["challenge_hex"]))))
        for (p in root.getValue("pad_challenge").arr()) {
            val f = p.obj().fields
            assertEquals(f.getValue("padded_hex").str(), Hex.lower(CompositeKey.padChallenge(hex(f["challenge_hex"]))))
        }
        assertFailsWith<IllegalArgumentException> { CompositeKey.yubikeySecret(ByteArray(19)) }
    }

    @Test fun keyFileRulesAndCreatedFile() {
        // "Create key file" writes exactly the layout of the vector (the spec's example key).
        val v2 = keyFiles.getValue("keyfile_xml_v2")
        assertContentEquals(resource(v2.getValue("file").str()), KeyFile.keepassXmlV2(hex(v2["key_hex"])))
        val made = KeyFile.newKeepassXmlV2(DetRand("keyfile"))
        assertEquals(32, KeyFile.keyFromBytes(made).size)
        // Only ASCII space, tab, CR and LF are whitespace: a VT, FF or NBSP inside the data is refused.
        val key = ByteArray(32) { it.toByte() }
        val b64 = java.util.Base64.getEncoder().encodeToString(key)
        fun v1(data: String) = "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>$data</Data></Key></KeyFile>".toByteArray(Charsets.UTF_8)
        assertContentEquals(key, KeyFile.keyFromBytes(v1(" \t\r\n" + b64.substring(0, 10) + "\n " + b64.substring(10) + " ")))
        assertFailsWith<KeyFileException> { KeyFile.keyFromBytes(v1(b64.substring(0, 10) + " " + b64.substring(10))) }
        assertFailsWith<KeyFileException> { KeyFile.keyFromBytes(v1(b64.dropLast(1))) } // padding missing
        assertFailsWith<KeyFileException> { KeyFile.keyFromBytes("<KeyFile><Key><Data>".toByteArray()) } // malformed XML
        // A UTF-8 BOM misses the XML rule: the file is hashed (rule 4), as in our importer.
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + v1(b64)
        assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(bom), KeyFile.keyFromBytes(bom))
        // A namespaced document has no plain Key/Data.
        assertFailsWith<KeyFileException> {
            KeyFile.keyFromBytes("<KeyFile xmlns=\"urn:x\"><Key><Data>$b64</Data></Key></KeyFile>".toByteArray())
        }
        // An external entity is never fetched: any DOCTYPE is refused.
        assertFailsWith<KeyFileException> {
            KeyFile.keyFromBytes("<?xml version=\"1.0\"?><!DOCTYPE KeyFile SYSTEM \"http://127.0.0.1:1/x.dtd\"><KeyFile/>".toByteArray())
        }
    }

    /** Android's expat parser has none of the Xerces features: the handler's own refusals must hold alone. */
    @Test fun keyFileXmlRefusalsHoldWithoutParserFeatures() {
        KeyFile.parserFeatures = false
        try {
            val docs = listOf(
                "<?xml version=\"1.0\"?><!DOCTYPE KeyFile SYSTEM \"http://127.0.0.1:1/x.dtd\"><KeyFile/>",
                "<?xml version=\"1.0\"?><!DOCTYPE KeyFile [<!ENTITY a \"b\">]><KeyFile><Key><Data>&a;</Data></Key></KeyFile>",
                "<?xml version=\"1.0\"?><!DOCTYPE KeyFile [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><KeyFile><Key><Data>&x;</Data></Key></KeyFile>",
            )
            for (d in docs) {
                val e = assertFailsWith<KeyFileException>(d) { KeyFile.keyFromBytes(d.toByteArray()) }
                assertEquals("Key file contains a DOCTYPE and was rejected", e.message, d)
            }
            // Without the XML prefix the file is not parsed at all: it is hashed (rule 4), so nothing is resolved.
            val bare = "<!DOCTYPE KeyFile [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><KeyFile/>".toByteArray()
            assertContentEquals(java.security.MessageDigest.getInstance("SHA-256").digest(bare), KeyFile.keyFromBytes(bare))
            // The handler path still reads ordinary key files.
            val v2 = keyFiles.getValue("keyfile_xml_v2")
            assertEquals(v2.getValue("key_hex").str(), Hex.lower(KeyFile.keyFromBytes(resource(v2.getValue("file").str()))))
            val v1 = keyFiles.getValue("keyfile_xml_v1")
            assertEquals(v1.getValue("key_hex").str(), Hex.lower(KeyFile.keyFromBytes(resource(v1.getValue("file").str()))))
        } finally {
            KeyFile.parserFeatures = true
        }
    }

    /** A v2 file whose stored slot or challenge was edited still decodes, but the right secrets no longer open it. */
    @Test fun tamperedV2FilesFailToUnwrap() {
        val c = case("android_apppassword_v2")
        val bytes = resource(c.getValue("file").str())
        val text = String(bytes, Charsets.ISO_8859_1)
        val keySecret = KeyFile.keyFromBytes(resource(keyFiles.getValue("keyfile_xml_v1").getValue("file").str()))
        val ykSecret = CompositeKey.yubikeySecret(hex(yubikey["response_hex"]))
        val pw = AppPasswordRecord.passwordBytes(c.getValue("password").str())
        fun patched(at: Int, ch: Char) = bytes.copyOf().also { it[at] = ch.code.toByte() }
        val slot = text.indexOf("\"slot\":2") + "\"slot\":".length
        val challenge = text.indexOf("\"challenge\":\"") + "\"challenge\":\"".length
        for (tampered in listOf(patched(slot, '1'), patched(challenge, if (text[challenge] == '0') '1' else '0'))) {
            val record = AppPasswordRecord.decode(tampered)
            assertTrue(record.factors != AppPasswordRecord.decode(bytes).factors)
            val e = assertFailsWith<AppPasswordException> { record.unwrapWithPassword(pw, secrets = listOf(keySecret, ykSecret)) }
            assertEquals(AppPasswordException.Kind.WRONG_PASSWORD, e.kind)
            // The recovery wrapper does not involve the list: the phrase still opens the edited file.
            assertContentEquals(hex(c["local_key_hex"]), record.unwrapWithPhrase(c.getValue("recovery_phrase").str()))
        }
        // An edited check fails before Argon2id as a mismatch.
        val check = text.indexOf("\"check\":\"") + "\"check\":\"".length
        val edited = AppPasswordRecord.decode(patched(check, if (text[check] == '0') '1' else '0'))
        assertFailsWith<FactorMismatchException> { edited.unwrapWithPassword(pw, secrets = listOf(keySecret, ykSecret)) }
    }

    @Test fun factorListIsStrict() {
        val good = case("keyfile_and_yubikey").getValue("info").str()
        assertEquals(good, String(CompositeKey.info(CompositeKey.parseList(good.toByteArray())), Charsets.US_ASCII))
        val bad = listOf(
            "[]",
            "[{\"check\":\"10ed9c05250cf31b\",\"kind\":\"keyfile\",\"slot\":2}]",
            "[{\"check\":\"10ED9C05250CF31B\",\"kind\":\"keyfile\"}]",
            "[{\"challenge\":\"${"a".repeat(64)}\",\"check\":\"d4cceb1d258554e0\",\"kind\":\"yubikey-hmac\",\"slot\":3}]",
            "[{\"challenge\":\"${"a".repeat(64)}\",\"check\":\"d4cceb1d258554e0\",\"kind\":\"yubikey-hmac\",\"slot\":true}]",
            // YubiKey before the key file, or two key files.
            "[{\"challenge\":\"${"a".repeat(64)}\",\"check\":\"d4cceb1d258554e0\",\"kind\":\"yubikey-hmac\",\"slot\":2},{\"check\":\"10ed9c05250cf31b\",\"kind\":\"keyfile\"}]",
            "[{\"check\":\"10ed9c05250cf31b\",\"kind\":\"keyfile\"},{\"check\":\"10ed9c05250cf31b\",\"kind\":\"keyfile\"}]",
            // Not canonical: key order and whitespace.
            "[{\"kind\":\"keyfile\",\"check\":\"10ed9c05250cf31b\"}]",
            "[{\"check\": \"10ed9c05250cf31b\",\"kind\":\"keyfile\"}]",
        )
        for (b in bad) assertFailsWith<IllegalArgumentException>(b) { CompositeKey.parseList(b.toByteArray()) }
    }

    @Test fun newChallengeIsRedrawnWhenItEndsInPadding() {
        val end00 = ByteArray(32) { 1 }.also { it[31] = 0 }
        val end20 = ByteArray(32) { 1 }.also { it[31] = 0x20 }
        val ok = ByteArray(32) { 1 }
        val r: RandomSource = QueueRandom(listOf(end00, end20, ok))
        assertContentEquals(ok, CompositeKey.newChallenge(r))
    }

    /** `app-password.bin` v1 (no factors) is byte for byte what it was before factors existed. */
    @Test fun appPasswordV1Unchanged() {
        val cheap = AppPasswordParams(memoryKiB = 8192, iterations = 1, parallelism = 1)
        val local = DetRand("app-password-v1-golden-local").bytes(32)
        val pw = AppPasswordRecord.passwordBytes("correct horse battery staple 42")
        val c = AppPasswordRecord.create(local, pw, DetRand("app-password-v1-golden"), cheap)
        // Written by the code before Task 9 (same inputs).
        val golden = "4c474b4150570100002000010104d99f5bff6d9c41cc461df7fc896769b35f985123b08986901784960671f6b4455e0dee1c34f9729627" +
            "54d900e3d797a1aafb30f2e6e3acea8266179f9be09d4db669f5bf72064f9a37bc9eb06bec9676ab6a4ae95372e7e6b02403d185785f30ba02" +
            "1c78f6089c0e112f808c6a40278b288d212a8fbfe781de6f9bdf43ab1f79d83da6030e4f1695596811f9f79755062b26ba23f7ec36"
        assertEquals(golden, Hex.lower(c.record.encode()))
        assertEquals(AppPasswordRecord.SIZE, c.record.encode().size)
        val back = AppPasswordRecord.decode(Hex.decode(golden))
        assertEquals(emptyList(), back.factors)
        assertContentEquals(Hex.decode(golden), back.encode())
        assertContentEquals(local, back.unwrapWithPassword(pw))
        assertContentEquals(local, back.unwrapWithPhrase(c.phrase))

        // Adding factors and removing them again gives a v1 file whose recovery wrapper never changed.
        val keySecret = DetRand("kf").bytes(32)
        val withFactor = back.withNewPassword(local, pw, DetRand("re1"), factors = listOf(FactorSpec.keyFile(CompositeKey.check(keySecret))), secrets = listOf(keySecret))
        val v2 = withFactor.encode()
        assertEquals(2, v2[6].toInt())
        assertContentEquals(Hex.decode(golden).copyOfRange(89, 165), v2.copyOfRange(v2.size - 76, v2.size), "recovery wrapper carried over")
        assertContentEquals(local, AppPasswordRecord.decode(v2).unwrapWithPhrase(c.phrase))
        val removed = AppPasswordRecord.decode(v2).withNewPassword(local, pw, DetRand("re2"))
        assertEquals(165, removed.encode().size)
        assertEquals(1, removed.encode()[6].toInt())
        assertContentEquals(Hex.decode(golden).copyOfRange(89, 165), removed.encode().copyOfRange(89, 165))
        assertContentEquals(local, removed.unwrapWithPassword(pw))
    }

    @Test fun appPasswordV2Vector() {
        val c = case("android_apppassword_v2")
        val bytes = resource(c.getValue("file").str())
        assertEquals(c.getValue("hex").str(), Hex.lower(bytes))
        assertEquals(c.getValue("size").long().toInt(), bytes.size)
        val record = AppPasswordRecord.decode(bytes)
        assertContentEquals(bytes, record.encode(), "decode then encode is byte-identical")
        val list = specs(c["factors"])
        assertEquals(list, record.factors)
        assertEquals(AppPasswordParams(8192, 1, 1), record.params)
        val l = CompositeKey.info(list).size
        assertEquals(c.getValue("password_aad_hex").str(), Hex.lower(bytes.copyOf(15 + l) + "|password".toByteArray()))
        assertEquals(c.getValue("recovery_aad_hex").str(), Hex.lower(Hex.decode(c.getValue("hex").str().substring(0, 26)).also { it[6] = 1 } + "|recovery".toByteArray()))

        val keySecret = KeyFile.keyFromBytes(resource(keyFiles.getValue("keyfile_xml_v1").getValue("file").str()))
        val ykSecret = CompositeKey.yubikeySecret(hex(yubikey["response_hex"]))
        val pw = AppPasswordRecord.passwordBytes(c.getValue("password").str())
        val local = hex(c["local_key_hex"])
        assertContentEquals(local, record.unwrapWithPassword(pw, secrets = listOf(keySecret, ykSecret)))
        assertContentEquals(local, record.unwrapWithPhrase(c.getValue("recovery_phrase").str()))
        val salt = bytes.copyOfRange(15 + l, 15 + l + 16)
        val out = BouncyCastleArgon2id().derive(pw, salt, 8192, 1, 1, 32)
        assertEquals(c.getValue("argon_out_hex").str(), Hex.lower(out))
        assertEquals(c.getValue("key_hex").str(), Hex.lower(CompositeKey.combine(out, list, listOf(keySecret, ykSecret))))

        // Every tampered row's key and AAD fail to open the stored password wrapper.
        val nonce = bytes.copyOfRange(15 + l + 16, 15 + l + 28)
        val sealed = bytes.copyOfRange(15 + l + 28, 15 + l + 76)
        for (t in c.getValue("tampered").arr()) {
            val f = t.obj().fields
            assertEquals("unwrap-fails", f.getValue("expect").str())
            try {
                CryptoBox.openGcm(hex(f["key_hex"]), nonce, sealed, hex(f["aad_hex"]))
                fail("tampered row ${f.getValue("name").str()} opened the wrapper")
            } catch (e: CryptoBoxException) {
            }
        }
        // Without the factors: "factor required", never "wrong password".
        assertFailsWith<FactorRequiredException> { record.unwrapWithPassword(pw) }
        val swapped = assertFailsWith<FactorMismatchException> { record.unwrapWithPassword(pw, secrets = listOf(ykSecret, ykSecret)) }
        assertEquals(FactorKind.KEYFILE, swapped.kind)
        val wrongYk = assertFailsWith<FactorMismatchException> { record.unwrapWithPassword(pw, secrets = listOf(keySecret, keySecret)) }
        assertEquals(FactorKind.YUBIKEY_HMAC, wrongYk.kind)
        // The right factors with a wrong password: a wrong password.
        val wrong = assertFailsWith<AppPasswordException> {
            record.unwrapWithPassword(AppPasswordRecord.passwordBytes("nope"), secrets = listOf(keySecret, ykSecret))
        }
        assertEquals(AppPasswordException.Kind.WRONG_PASSWORD, wrong.kind)
    }

    @Test fun v2ReaderRefusesDamagedFiles() {
        val bytes = resource("android_apppassword_v2.bin")
        fun refused(b: ByteArray) {
            val e = assertFailsWith<AppPasswordException> { AppPasswordRecord.decode(b) }
            assertEquals(AppPasswordException.Kind.MALFORMED, e.kind)
        }
        refused(bytes.copyOf(bytes.size - 1))
        refused(bytes + 0)
        refused(bytes.copyOf().also { it[6] = 3 })
        refused(bytes.copyOf().also { it[13] = 0; it[14] = 0 }) // L = 0
        refused(bytes.copyOf().also { it[15 + 2] = ' '.code.toByte() }) // the list is no longer canonical JSON
        refused(bytes.copyOf().also { it[7] = 0x7f }) // memory outside the v1 limits
    }

    @Test fun mismatchBeforeKdf() {
        val argon = CountingArgon()
        val c = case("android_apppassword_v2")
        val record = AppPasswordRecord.decode(resource(c.getValue("file").str()))
        val pw = AppPasswordRecord.passwordBytes(c.getValue("password").str())
        val otherFile = KeyFile.keyFromBytes(resource(keyFiles.getValue("keyfile_xml_v2").getValue("file").str()))
        val ykSecret = CompositeKey.yubikeySecret(hex(yubikey["response_hex"]))
        val e = assertFailsWith<FactorMismatchException> { record.unwrapWithPassword(pw, argon, listOf(otherFile, ykSecret)) }
        assertEquals(FactorKind.KEYFILE, e.kind)
        assertFailsWith<FactorRequiredException> { record.unwrapWithPassword(pw, argon, listOf(ykSecret)) }
        assertEquals(0, argon.calls, "no Argon2id run for a missing or wrong factor")
    }
}
