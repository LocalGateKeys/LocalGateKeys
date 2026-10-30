package app.localgatekeys.core.importing

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.Deflater
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Android importers against the desktop's own results: the `.expected.json` files under `tests/vectors/import/<format>` (written by
 * `scripts/gen_mac_backup_vectors.py` from the Windows importers over `tests/fixtures/imports`), the same vectors the
 * Mac and iPhone tests read.
 */
class ImportVectorsTest {
    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
    private val vectors = File(repo, "tests/vectors/import")

    private fun json(f: File): PyJson = PyJson.parse(f.readText(Charsets.UTF_8))

    private fun input(v: PyJson): ByteArray = File(repo, v["input"]!!.str).readBytes()

    private fun mapping(v: PyJson, data: ByteArray): GenericCsvMapping? {
        val m = v["mapping"] ?: return null
        val header = GenericCsv.header(data)
        fun idx(k: String): Int? = m[k]?.let { name -> header.indexOf(name.str).takeIf { it >= 0 } }
        return GenericCsvMapping(idx("title"), idx("url"), idx("username"), idx("password"), idx("notes"), idx("totp"))
    }

    private fun run(v: PyJson, password: String? = null): ImportResult {
        val data = input(v)
        val format = ImportFormat.fromRaw(v["format"]!!.str)!!
        val pw = password ?: (v["password"] as? PyJson.Str)?.v
        return ImportSource.candidates(data, format, ImportOptions(pw, mapping(v, data)))
    }

    private fun normalised(c: ImportCandidate): Map<String, PyJson> {
        fun s(x: String) = PyJson.Str(x)
        fun n(x: Long?) = x?.let { PyJson.Int(it) } ?: PyJson.Null
        fun dict(m: Map<String, String>) = PyJson.Obj(m.entries.sortedBy { it.key }.map { it.key to s(it.value) })
        return mapOf(
            "kind" to s(c.kind.raw), "title" to s(c.title), "username" to s(c.username), "password" to s(c.password),
            "urls" to PyJson.Arr(c.urls.map(::s)), "notes" to s(c.notes), "totp_uri" to s(c.totp), "folder" to s(c.folder),
            "favorite" to PyJson.Bool(c.favourite),
            "custom_fields" to PyJson.Arr(
                c.customFields.map { PyJson.Obj(listOf("hidden" to PyJson.Bool(it.hidden), "name" to s(it.name), "value" to s(it.value))) },
            ),
            "created" to n(c.created), "modified" to n(c.modified), "tags" to PyJson.Arr(c.tags.map(::s)),
            "identity" to dict(c.identity), "card" to dict(c.card), "source_row" to n(c.sourceRow?.toLong()),
        )
    }

    /** Key order does not matter for objects: compare sorted. */
    private fun canon(v: PyJson): PyJson = when (v) {
        is PyJson.Obj -> PyJson.Obj(v.pairs.sortedBy { it.first }.map { it.first to canon(it.second) })
        is PyJson.Arr -> PyJson.Arr(v.items.map(::canon))
        else -> v
    }

    private fun check(f: File): Int {
        val name = f.relativeTo(vectors).path
        val v = json(f)
        val error = v["error"]
        if (error != null) {
            val e = assertFailsWith<ImportException>(name) { run(v) }
            when (error["type"]!!.str) {
                "password_required" -> assertEquals(ImportException.Kind.NEEDS_PASSWORD, e.kind, name)
                "wrong_password" -> {
                    assertTrue(e.isWrongPassword, name)
                    assertTrue(e.message.startsWith(error["message"]!!.str), "$name: ${e.message}")
                }
                else -> assertEquals(error["message"]!!.str, e.message, name)
            }
            return 0
        }
        val result = run(v)
        val expected = v["result"]!!
        assertEquals(expected["diagnostics"]!!.list.map { it.str }, result.skipped.map { it.message }, name)
        val records = expected["records"]!!.list
        assertEquals(records.size, result.candidates.size, name)
        for ((i, pair) in result.candidates.zip(records).withIndex()) {
            val got = normalised(pair.first)
            for ((key, want) in (pair.second as PyJson.Obj).pairs) {
                val g = got[key] ?: continue
                assertEquals(canon(want).repr, canon(g).repr, "$name record $i $key")
            }
        }
        return records.size
    }

    private fun dir(name: String): List<File> =
        File(vectors, name).listFiles { f -> f.name.endsWith(".expected.json") }!!.sortedBy { it.name }

    @Test
    fun browserCsvsMatchWindows() {
        var n = 0
        for (d in listOf("appleCSV", "chrome", "firefox")) for (f in dir(d)) n += check(f)
        assertTrue(n >= 8)
    }

    @Test
    fun bitwardenJsonAndCsvMatchWindows() {
        for (f in dir("bitwarden")) check(f)
    }

    @Test
    fun bitwardenPasswordProtectedMatchesWindows() {
        for (f in dir("bitwardenEncrypted")) check(f)
        // Both KDFs open the same document as its plain export.
        val plain = run(json(File(vectors, "bitwarden/bitwarden_types.json.expected.json")))
        val pbkdf2 = run(json(File(vectors, "bitwardenEncrypted/bitwarden_pbkdf2.json.expected.json")))
        val argon = run(json(File(vectors, "bitwardenEncrypted/bitwarden_argon2.json.expected.json")))
        assertEquals(plain, pbkdf2)
        assertEquals(plain, argon)
    }

    @Test
    fun wrongBitwardenPasswordSaysSo() {
        val v = json(File(vectors, "bitwardenEncrypted/bitwarden_protected.json.wrong.expected.json"))
        val e = assertFailsWith<ImportException> { run(v) }
        assertEquals(ImportException.Kind.WRONG_PASSWORD, e.kind)
        assertEquals("Wrong password or corrupted export (MAC mismatch)", e.message)
        assertEquals(ImportException.Kind.NEEDS_PASSWORD, assertFailsWith<ImportException> { run(v, password = "") }.kind)
        // The message never carries the password.
        assertTrue("not the password" !in e.message)
    }

    @Test
    fun onePassword1puxMatchesWindows() {
        for (f in dir("onePassword1PUX")) check(f)
    }

    @Test
    fun genericCsvWithMappingMatchesWindows() {
        for (f in dir("generic")) check(f)
        // The suggested mapping is the Windows `guess_mapping`.
        val cases = json(File(vectors, "generic_mapping.json")).list
        for (c in cases) {
            val data = File(repo, c["input"]!!.str).readBytes()
            val header = GenericCsv.header(data)
            assertEquals(c["header"]!!.list.map { it.str }, header, c["input"]!!.str)
            val m = GenericCsv.suggestMapping(header)
            val want = c["mapping"]!!
            for ((k, got) in listOf("title" to m.title, "url" to m.url, "username" to m.username, "password" to m.password, "notes" to m.notes, "totp" to m.totp)) {
                assertEquals(want[k]?.str, got?.let { header[it] }, "${c["input"]!!.str} $k")
            }
        }
    }

    @Test
    fun genericCsvUsesTheChosenColumns() {
        val csv = "Site,Who,Secret,Memo\nhttps://a.example,alex,pw-a,first\n,,,only a note\n".toByteArray()
        val r = ImportSource.candidates(csv, ImportFormat.GENERIC, ImportOptions(mapping = GenericCsvMapping(url = 0, username = 1, password = 2, notes = 3)))
        assertEquals(2, r.candidates.size)
        val login = r.candidates[0]
        assertEquals(ImportCandidate.Kind.LOGIN, login.kind)
        assertEquals("a.example", login.title)
        assertEquals("alex", login.username)
        assertEquals("pw-a", login.password)
        assertEquals(ImportCandidate.Kind.NOTE, r.candidates[1].kind)
        val bad = assertFailsWith<ImportException> {
            ImportSource.candidates(csv, ImportFormat.GENERIC, ImportOptions(mapping = GenericCsvMapping(password = 9)))
        }
        assertEquals("Column 10 does not exist in the CSV header", bad.message)
    }

    @Test
    fun detectMatchesWindows() {
        var checked = 0
        for (c in json(File(vectors, "detect.json")).list) {
            val path = c["input"]!!.str
            val data = File(repo, path).readBytes()
            val want = (c["format"] as? PyJson.Str)?.v
            assertEquals(want, ImportDetect.detect(data, path.substringAfterLast('/'))?.raw, path)
            checked++
        }
        assertTrue(checked > 50)
    }

    @Test
    fun oversizeFilesAreRefused() {
        val big = ByteArray(ImportSource.MAX_ARCHIVE_BYTES + 1) { 'a'.code.toByte() }
        assertEquals("Import source exceeds 64 MiB", assertFailsWith<ImportException> { ImportSource.candidates(big, ImportFormat.CHROME) }.message)
        assertNull(ImportDetect.detect(big, "big.csv"))
        // Text formats keep the Windows 8 MiB limit.
        val csv = ("name,url,username,password\n" + "x".repeat(ImportSource.MAX_SOURCE_BYTES)).toByteArray()
        assertEquals(ImportException.Kind.TOO_LARGE, assertFailsWith<ImportException> { ImportSource.candidates(csv, ImportFormat.CHROME) }.kind)
    }

    @Test
    fun csvQuotingBomAndLineEnds() {
        val text = "﻿name,url,username,password,note\r\n\"Quoted, name\",https://q.example,\"a\"\"b\",pw,\"line1\nline2\"\rplain,https://p.example,u,p2,\n"
        val r = ImportSource.candidates(text.toByteArray(), ImportFormat.CHROME)
        assertEquals(2, r.candidates.size)
        assertEquals("Quoted, name", r.candidates[0].title)
        assertEquals("a\"b", r.candidates[0].username)
        assertEquals("line1\nline2", r.candidates[0].notes)
        assertEquals("p2", r.candidates[1].password)
    }

    private fun zip(vararg members: Pair<String, ByteArray>, deflate: Boolean = true): ByteArray {
        val out = ByteArrayOutputStream()
        val central = ByteArrayOutputStream()
        fun le16(o: ByteArrayOutputStream, v: Int) { o.write(v and 0xFF); o.write((v shr 8) and 0xFF) }
        fun le32(o: ByteArrayOutputStream, v: Long) { le16(o, (v and 0xFFFF).toInt()); le16(o, ((v shr 16) and 0xFFFF).toInt()) }
        for ((name, data) in members) {
            val payload = if (deflate) {
                val d = Deflater(9, true); d.setInput(data); d.finish()
                val buf = ByteArray(data.size + 1024); val n = d.deflate(buf); d.end(); buf.copyOf(n)
            } else data
            val crc = CRC32().apply { update(data) }.value
            val offset = out.size().toLong()
            val nb = name.toByteArray()
            le32(out, 0x04034B50); le16(out, 20); le16(out, 0); le16(out, if (deflate) 8 else 0); le32(out, 0)
            le32(out, crc); le32(out, payload.size.toLong()); le32(out, data.size.toLong()); le16(out, nb.size); le16(out, 0)
            out.write(nb); out.write(payload)
            le32(central, 0x02014B50); le16(central, 20); le16(central, 20); le16(central, 0); le16(central, if (deflate) 8 else 0)
            le32(central, 0); le32(central, crc); le32(central, payload.size.toLong()); le32(central, data.size.toLong())
            le16(central, nb.size); le16(central, 0); le16(central, 0); le16(central, 0); le16(central, 0); le32(central, 0); le32(central, offset)
            central.write(nb)
        }
        val cdOffset = out.size().toLong()
        val cd = central.toByteArray()
        out.write(cd)
        le32(out, 0x06054B50); le16(out, 0); le16(out, 0); le16(out, members.size); le16(out, members.size)
        le32(out, cd.size.toLong()); le32(out, cdOffset); le16(out, 0)
        return out.toByteArray()
    }

    @Test
    fun onePasswordZipBuiltHereReads() {
        val exportData = File(repo, "tests/fixtures/imports/onepassword/export.data").readBytes()
        val z = zip("export.attributes" to "{}".toByteArray(), "export.data" to exportData)
        assertEquals(ImportFormat.ONE_PASSWORD_1PUX, ImportDetect.detect(z, "x.1pux"))
        val viaZip = ImportSource.candidates(z, ImportFormat.ONE_PASSWORD_1PUX)
        val bare = ImportSource.candidates(exportData, ImportFormat.ONE_PASSWORD_1PUX)
        assertEquals(bare, viaZip)
        assertTrue(viaZip.candidates.isNotEmpty())
    }

    @Test
    fun zipCapsAreEnforced() {
        // A name pointing outside the archive.
        val evil = zip("../export.data" to "{}".toByteArray())
        assertEquals(ZipReader.Failure.UNSAFE_NAME, assertFailsWith<ZipReader.ZipException> { ZipReader(evil, 1 shl 20, 10) }.failure)
        // Too many entries.
        val many = zip("a" to byteArrayOf(1), "b" to byteArrayOf(2), "c" to byteArrayOf(3))
        assertEquals(ZipReader.Failure.TOO_MANY_ENTRIES, assertFailsWith<ZipReader.ZipException> { ZipReader(many, 1 shl 20, 2) }.failure)
        // A zip bomb: 4 MiB of zeros compresses far beyond the 200x ratio.
        val bomb = zip("export.data" to ByteArray(4 * 1024 * 1024))
        val reader = ZipReader(bomb, 1 shl 24, 10)
        assertEquals(ZipReader.Failure.RATIO, assertFailsWith<ZipReader.ZipException> { reader.read(reader.entry("export.data")!!, 1 shl 24) }.failure)
        assertEquals(
            "A file inside the zip archive is compressed suspiciously well and was refused",
            assertFailsWith<ImportException> { ImportSource.candidates(bomb, ImportFormat.ONE_PASSWORD_1PUX) }.message,
        )
        // A decompressed size over the caller's limit.
        val small = zip("x" to ByteArray(5000) { it.toByte() })
        val r2 = ZipReader(small, 1 shl 20, 10)
        assertEquals(ZipReader.Failure.TOO_LARGE, assertFailsWith<ZipReader.ZipException> { r2.read(r2.entry("x")!!, 100) }.failure)
        // Duplicate names.
        val dup = zip("a" to byteArrayOf(1), "a" to byteArrayOf(2))
        assertEquals(ZipReader.Failure.DUPLICATE_NAME, assertFailsWith<ZipReader.ZipException> { ZipReader(dup, 1 shl 20, 10) }.failure)
    }

    @Test
    fun candidatesNeverPrintSecrets() {
        val r = ImportSource.candidates("name,url,username,password\nn,https://x.example,user,hunter2\n".toByteArray(), ImportFormat.CHROME)
        assertTrue("hunter2" !in r.toString())
        assertTrue("hunter2" !in ImportOptions("hunter2").toString())
    }
}
