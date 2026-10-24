package app.localgatekeys.android.vault

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.KeyValueStore
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Ports of ios/AppSharedTests/LocalStoreTests.swift, plus the Android crash, stale, order and locking cases. */
class LocalStoreTest {
    @get:Rule val tmp = TemporaryFolder()

    /** Deterministic, non-repeating: SHA-256 of a running counter. */
    private class FixedRandom : RandomSource {
        private var n = 0L

        @Synchronized override fun bytes(count: Int): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            while (out.size() < count) {
                n++
                out.write(MessageDigest.getInstance("SHA-256").digest(java.nio.ByteBuffer.allocate(8).putLong(n).array()))
            }
            return out.toByteArray().copyOf(count)
        }
    }

    private lateinit var dir: File
    private val key = ByteArray(32) { 9 }
    private val noSync: (File) -> Unit = {}

    @Before fun setUp() {
        dir = File(tmp.root, "Vault")
    }

    private fun open(settings: AppSettings? = null, k: ByteArray = key, d: File = dir, dirSync: (File) -> Unit = noSync) =
        LocalStore.openForTest(d, k, FixedRandom(), settings, dirSync)

    private fun obj(vararg p: Pair<String, JsonValue>) = JsonValue.Obj(mapOf(*p))
    private fun s(v: String) = JsonValue.Str(v)

    private val secretPassword = "hunter2-very-secret"

    private fun sampleChange(base: Long): StoreChange {
        val w1 = CanonicalJson.parse(
            ("""{"ns":"login","record":{"id":"a1","password":"$secretPassword","price":100.0,"big":1e+16,"n":3,"updated_at":7}}""")
                .toByteArray(),
        )
        val w2 = CanonicalJson.parse("""{"ns":"note","record":{"id":"b2","text":"héllo ☃","updated_at":9}}""".toByteArray())
        val identity = DeviceIdentity.generate("phone-1", FixedRandom())
        val sync = SyncGroupState(
            "grp", 2, ByteArray(32) { 7 }, identity, "inst", true, mapOf("desk" to 4L), mapOf("desk" to "ab"),
            1, listOf("desk", "phone-1"), byteArrayOf(1, 2, 3), 5,
        )
        return StoreChange(
            base, mapOf("a1" to w1, "b2" to w2),
            mapOf("a1" to SyncMeta.live(w1, mapOf("phone-1" to 1L)), "gone" to SyncMeta.tomb(mapOf("desk" to 2L), 50)),
            sync,
        )
    }

    private fun empty(base: Long) = StoreChange(base, emptyMap(), emptyMap(), null)

    private fun note(i: Int): JsonValue = obj("ns" to s("item"), "record" to obj("id" to s("n$i"), "kind" to s("note")))

    private fun gens(): List<String> = dir.list()!!.filter { it.startsWith("g") }.sorted()

    private fun thrown(block: () -> Unit): LocalStoreException {
        try {
            block()
        } catch (e: LocalStoreException) {
            return e
        }
        fail("expected LocalStoreException")
        throw AssertionError()
    }

    private fun kind(block: () -> Unit): LocalStoreException.Kind = thrown(block).kind

    // test_commit_publishes_plan_full_hint
    @Test fun commit_publishes_plan_full_hint() {
        val hints = AppSettings(MemoryStore())
        val store = open(hints)
        val records = LinkedHashMap<String, JsonValue>()
        for (i in 0 until 3) records["n$i"] = note(i)
        store.commit(StoreChange(0, HashMap(records), emptyMap(), null))
        assertNull("room left", hints.planFullRevision)
        records["n3"] = note(3)
        store.commit(StoreChange(1, HashMap(records), emptyMap(), null))
        assertEquals(2L, hints.planFullRevision)
        assertEquals("readable before unlock (plain CURRENT)", 2L, LocalStore.committedRevision(dir))
        records.remove("n3")
        store.commit(StoreChange(2, HashMap(records), emptyMap(), null))
        assertNull(hints.planFullRevision)
        assertNull(LocalStore.committedRevision(File(dir, "missing")))
    }

    @Test fun commit_without_settings_publishes_nothing_and_works() {
        val store = open(null)
        store.commit(StoreChange(0, mapOf("n0" to note(0)), emptyMap(), null))
        assertEquals(1L, store.load().revision)
    }

    // test_store_round_trip
    @Test fun store_round_trip() {
        val store = open()
        assertEquals(StoreSnapshot(), store.load())
        val change = sampleChange(0)
        store.commit(change)

        val snap = open().load()
        assertEquals(1L, snap.revision)
        assertEquals(change.records, snap.records)
        assertEquals(change.meta, snap.meta)
        assertEquals(change.sync, snap.sync)
        // Byte-identical republish: floats stay floats.
        assertArrayEquals(
            CanonicalJson.encode(change.records.getValue("a1"), Dialect.UTF8),
            CanonicalJson.encode(snap.records.getValue("a1"), Dialect.UTF8),
        )

        // Stale base is refused and leaves the store untouched.
        assertEquals(LocalStoreException.Kind.STALE, kind { store.commit(empty(0)) })
        assertEquals(snap, store.load())

        // Next commit replaces everything; only two generations remain on disk.
        store.commit(empty(1))
        store.commit(StoreChange(2, mapOf("b2" to change.records.getValue("b2")), emptyMap(), null))
        val last = store.load()
        assertEquals(3L, last.revision)
        assertEquals(listOf("b2"), last.records.keys.toList())
        assertNull(last.sync)
        assertEquals(listOf("g2", "g3"), gens())
    }

    // M-7: the pinned view signing keys (Swift LocalStore `view_signers`, main)
    @Test fun view_signers_round_trip() {
        val store = open()
        val base = sampleChange(0)
        val signers = mapOf("desk" to Base64Std.encode(ByteArray(32) { 4 }), "phone-1" to Base64Std.encode(ByteArray(32) { 5 }))
        val change = StoreChange(0, base.records, base.meta, base.sync!!.copy(viewSigners = signers))
        store.commit(change)
        val back = open().load().sync!!
        assertEquals(signers, back.viewSigners)
        assertEquals(change.sync, back)
        // Same JSON as the iPhone: an object of strings under "view_signers".
        val json = (LocalStore.encodeSync(change.sync!!) as JsonValue.Obj).fields
        assertEquals(obj("desk" to s(signers.getValue("desk")), "phone-1" to s(signers.getValue("phone-1"))), json["view_signers"])
        assertEquals(change.sync, LocalStore.decodeSync(LocalStore.encodeSync(change.sync!!)))
    }

    @Test fun a_state_stored_before_the_pins_reads_with_none_and_a_bad_pin_is_corrupt() {
        val state = sampleChange(0).sync!!.copy(viewSigners = mapOf("desk" to "a2V5"))
        val fields = (LocalStore.encodeSync(state) as JsonValue.Obj).fields
        val old = JsonValue.Obj(fields - "view_signers")
        assertEquals(emptyMap<String, String>(), LocalStore.decodeSync(old).viewSigners)
        assertEquals(state.copy(viewSigners = emptyMap()), LocalStore.decodeSync(old))
        for (bad in listOf(obj("desk" to JsonValue.Int(1)), JsonValue.Str("x"), JsonValue.Null)) {
            assertEquals(LocalStoreException.Kind.CORRUPT, kind { LocalStore.decodeSync(JsonValue.Obj(fields + ("view_signers" to bad))) })
        }
    }

    @Test fun a_commit_keeps_the_signers() {
        val store = open()
        val base = sampleChange(0)
        val signers = mapOf("desk" to Base64Std.encode(ByteArray(32) { 4 }))
        store.commit(StoreChange(0, base.records, base.meta, base.sync!!.copy(viewSigners = signers)))
        // A later commit (an edit) carries the loaded state on: the pins stay.
        val snap = store.load()
        store.commit(StoreChange(snap.revision, snap.records + ("n9" to note(9)), snap.meta, snap.sync))
        val again = open().load()
        assertEquals(2L, again.revision)
        assertEquals(signers, again.sync!!.viewSigners)
        assertTrue(again.records.containsKey("n9"))
    }

    // test_files_are_encrypted_and_tamper_detected
    @Test fun files_are_encrypted_and_tamper_detected() {
        val store = open()
        store.commit(sampleChange(0))
        val gen = File(dir, "g1")
        for (name in gen.list()!!) {
            val d = String(File(gen, name).readBytes(), Charsets.ISO_8859_1)
            assertFalse(name, d.contains(secretPassword))
            assertFalse(name, d.contains("login"))
        }
        // Swapping item blobs between ids fails authentication.
        val a = File(gen, "i0.blob").readBytes()
        val b = File(gen, "i1.blob").readBytes()
        File(gen, "i0.blob").writeBytes(b)
        File(gen, "i1.blob").writeBytes(a)
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.load() })
        // A different local key cannot open the store.
        val e = thrown { open(k = ByteArray(32) { 8 }).load() }
        assertEquals(LocalStoreException.Kind.CORRUPT, e.kind)
        assertEquals("authentication", e.detail)
    }

    @Test fun a_key_that_is_not_32_bytes_is_refused() {
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { open(k = ByteArray(31)) })
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { open(k = ByteArray(33)) })
        assertFalse("no directory is made for a bad key", dir.exists())
    }

    @Test fun public_open_uses_the_real_directory_sync() {
        val store = LocalStore.open(dir, key, FixedRandom(), null)
        store.commit(sampleChange(0))
        assertEquals(1L, store.load().revision)
    }

    // test_uncommitted_generation_is_invisible
    @Test fun uncommitted_generation_is_invisible() {
        val store = open()
        store.commit(sampleChange(0))
        val before = store.load()
        File(dir, "g1").copyRecursively(File(dir, "g2"))
        assertTrue(File(dir, "tmp-x").mkdir())
        assertEquals(before, store.load())
        store.commit(empty(1))
        assertEquals(emptyMap<String, JsonValue>(), store.load().records)
        assertFalse(File(dir, "tmp-x").exists())
    }

    // test_current_pointing_at_missing_generation_falls_back
    @Test fun current_pointing_at_missing_generation_falls_back() {
        val store = open()
        store.commit(sampleChange(0))
        store.commit(empty(1))
        val g1 = store.load()
        assertEquals(2L, g1.revision)
        File(dir, "CURRENT").writeBytes("3\n".toByteArray())
        assertTrue(File(dir, "g3").mkdir())
        val snap = store.load()
        assertEquals(g1, snap)
        store.commit(empty(snap.revision))
        assertEquals(4L, store.load().revision)
        // Nothing readable at all: corrupt, never an empty vault.
        for (g in listOf("g3", "g4")) File(dir, g).deleteRecursively()
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.load() })
    }

    // test_tampered_current_generation_throws_without_rollback
    @Test fun tampered_current_generation_throws_without_rollback() {
        val store = open()
        store.commit(sampleChange(0))
        store.commit(StoreChange(1, mapOf("b2" to sampleChange(0).records.getValue("b2")), emptyMap(), null))
        val blob = File(dir, "g2/i0.blob")
        val d = blob.readBytes()
        d[d.size - 1] = (d[d.size - 1].toInt() xor 1).toByte()
        blob.writeBytes(d)
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.load() })
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.commit(empty(1)) })
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.commit(empty(2)) })
        assertEquals(listOf("g1", "g2"), gens())
        assertEquals("2\n", File(dir, "CURRENT").readText(Charsets.US_ASCII))
    }

    // test_read_racing_a_prune_retries_from_current
    @Test fun read_racing_a_prune_retries_from_current() {
        val store = open()
        store.commit(sampleChange(0))
        var fired = false
        store.afterStateRead = { rev ->
            if (!fired) {
                fired = true
                // Two commits land mid-read: CURRENT moves to rev + 2 and generation `rev` is pruned.
                store.commit(sampleChange(rev))
                store.commit(sampleChange(rev + 1))
            }
        }
        val snap = store.load()
        assertTrue(fired)
        assertEquals(3L, snap.revision)
        assertEquals(2, snap.records.size)

        // CURRENT did not move: a missing item blob is damage and still throws.
        store.afterStateRead = null
        assertTrue(File(dir, "g3/i0.blob").delete())
        val e = thrown { store.load() }
        assertEquals(LocalStoreException.Kind.IO, e.kind)
        assertEquals("missing i0.blob", e.detail)
    }

    // test_missing_current_with_generations_is_corrupt
    @Test fun missing_current_with_generations_is_corrupt() {
        val store = open()
        store.commit(sampleChange(0))
        assertTrue(File(dir, "CURRENT").delete())
        val e = thrown { store.load() }
        assertEquals(LocalStoreException.Kind.CORRUPT, e.kind)
        assertEquals("CURRENT missing but generations exist", e.detail)
        assertEquals(LocalStoreException.Kind.CORRUPT, kind { store.commit(empty(0)) })
        assertTrue(File(dir, "g1/state.blob").exists())
    }

    @Test fun unparsable_current_is_corrupt() {
        val store = open()
        store.commit(sampleChange(0))
        for (bad in listOf("", "abc\n", "0\n", "-3\n")) {
            File(dir, "CURRENT").writeBytes(bad.toByteArray())
            val e = thrown { store.load() }
            assertEquals(bad, LocalStoreException.Kind.CORRUPT, e.kind)
            assertEquals("CURRENT", e.detail)
        }
    }

    @Test fun short_blob_is_corrupt() {
        val store = open()
        store.commit(sampleChange(0))
        File(dir, "g1/i0.blob").writeBytes(ByteArray(27))
        val e = thrown { store.load() }
        assertEquals(LocalStoreException.Kind.CORRUPT, e.kind)
        assertEquals("blob", e.detail)
    }

    // File-level part of test_store_files_without_their_key... and test_empty_or_missing_directory...
    @Test fun has_store_files_sees_current_or_a_generation_only() {
        assertFalse("missing directory", LocalStore.hasStoreFiles(dir))
        assertTrue(dir.mkdirs())
        File(dir, ".lock").writeBytes(ByteArray(0)) // a lock file alone holds no vault
        assertFalse(LocalStore.hasStoreFiles(dir))
        File(dir, "gx").mkdir()
        File(dir, "g").mkdir()
        File(dir, "tmp-1").mkdir()
        assertFalse(LocalStore.hasStoreFiles(dir))
        File(dir, "g12").mkdir()
        assertTrue(LocalStore.hasStoreFiles(dir))
        File(dir, "g12").delete()
        File(dir, "CURRENT").writeBytes("1\n".toByteArray())
        assertTrue(LocalStore.hasStoreFiles(dir))
    }

    @Test fun open_creates_only_the_directory() {
        open()
        assertTrue(dir.isDirectory)
        assertFalse(LocalStore.hasStoreFiles(dir))
        assertEquals(0L, open().load().revision)
    }

    @Test fun set_aside_renames_and_remove_set_aside_deletes() {
        open().commit(sampleChange(0))
        LocalStore.setAside(dir, 1_700_000_000)
        assertFalse(dir.exists())
        val first = File(tmp.root, "Vault-unreadable-1700000000")
        assertTrue(first.isDirectory)
        assertTrue(File(first, "CURRENT").exists())
        // A second set-aside in the same second gets a suffix.
        open().commit(sampleChange(0))
        LocalStore.setAside(dir, 1_700_000_000)
        assertTrue(File(tmp.root, "Vault-unreadable-1700000000-1").isDirectory)
        File(tmp.root, "Vaultx").mkdir()
        LocalStore.removeSetAside(dir)
        assertEquals(listOf("Vaultx"), tmp.root.list()!!.toList())
        LocalStore.removeSetAside(File(tmp.root, "nothing-here/Vault")) // best effort, never throws
    }

    // --- Android: crash, stale, durability order, locking -------------------------------------

    @Test fun crash_between_tmp_and_current_keeps_previous_revision() {
        val store = open()
        store.commit(sampleChange(0))
        val before = store.load()
        // The new generation is renamed into place, then the process dies before CURRENT moves. A thrown exception
        // cleans the generation up, which a dead process cannot: keep a copy at the seam and put it back after.
        val crashCopy = File(dir.parentFile, "g2-crash-copy")
        store.beforeCurrentWrite = {
            File(dir, "g2").copyRecursively(crashCopy)
            throw IOException("simulated process death")
        }
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(StoreChange(1, mapOf("n0" to note(0)), emptyMap(), null)) })
        assertFalse("an exception removes the unpublished generation", File(dir, "g2").exists())
        assertTrue(crashCopy.renameTo(File(dir, "g2"))) // what a real crash leaves behind
        assertEquals("1\n", File(dir, "CURRENT").readText(Charsets.US_ASCII))

        // The next unlock (a new instance) opens the last committed revision.
        val reopened = open()
        assertEquals(before, reopened.load())
        assertEquals(1L, LocalStore.committedRevision(dir))
        // A new commit based on it succeeds and replaces the leftover generation.
        reopened.commit(StoreChange(1, mapOf("n1" to note(1)), emptyMap(), null))
        val after = reopened.load()
        assertEquals(2L, after.revision)
        assertEquals(setOf("n1"), after.records.keys)
        assertEquals(listOf("g1", "g2"), gens())
    }

    /** A lock (beginClose) during the first ever commit must not leave g1 without CURRENT (that reads as damage). */
    @Test fun lock_during_the_first_commit_leaves_an_empty_store() {
        val store = open()
        store.beforeCurrentWrite = { store.beginClose() }
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.commit(sampleChange(0)) })
        assertEquals(emptyList<String>(), gens())
        assertFalse(File(dir, "CURRENT").exists())
        val fresh = open()
        assertEquals(0L, fresh.load().revision)
        assertTrue(fresh.load().records.isEmpty())
        fresh.commit(sampleChange(0))
        assertEquals(1L, open().load().revision)
    }

    @Test fun lock_after_the_generation_rename_removes_the_stray_generation() {
        val store = open()
        store.commit(sampleChange(0))
        store.beforeCurrentWrite = { store.beginClose() }
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.commit(empty(1)) })
        assertEquals("the stray g2 is gone", listOf("g1"), gens())
        val fresh = open()
        assertEquals(1L, fresh.load().revision)
        fresh.commit(empty(1))
        assertEquals(2L, open().load().revision)
    }

    /** A lock while the CURRENT temp file is being synced never publishes it (checked just before the rename). */
    @Test fun lock_during_the_current_temp_sync_never_publishes() {
        for (startRev in listOf(0L, 1L)) {
            dir = File(tmp.root, "Vault$startRev")
            val store = open()
            if (startRev == 1L) store.commit(sampleChange(0))
            store.beforeCurrentRename = { store.beginClose() }
            assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.commit(if (startRev == 0L) sampleChange(0) else empty(1)) })
            assertEquals(if (startRev == 0L) null else 1L, LocalStore.committedRevision(dir))
            assertEquals(if (startRev == 0L) emptyList() else listOf("g1"), gens())
            assertEquals(emptyList<String>(), dir.list()!!.filter { it.endsWith(".tmp") })
            assertEquals(startRev, open().load().revision)
        }
    }

    @Test fun crash_before_the_rename_leaves_only_ignorable_tmp_files() {
        val store = open()
        store.commit(sampleChange(0))
        val before = store.load()
        // Process death while writing the new generation: a half-written tmp dir and a stray CURRENT temp file.
        val half = File(dir, "tmp-dead").also { it.mkdir() }
        File(half, "state.blob").writeBytes(ByteArray(5))
        File(dir, ".CURRENT.dead.tmp").writeBytes("2\n".toByteArray())
        assertEquals(before, open().load())
        open().commit(empty(1))
        assertFalse(half.exists())
        assertEquals(2L, open().load().revision)
    }

    @Test fun failed_commit_cleans_its_tmp_directory() {
        val store = open(dirSync = { d -> if (d.name.startsWith("tmp-")) throw IOException("disk full") })
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(sampleChange(0)) })
        assertEquals(emptyList<String>(), dir.list()!!.filter { it.startsWith("tmp-") })
        assertEquals(StoreSnapshot(), store.load())
    }

    @Test fun failed_current_rename_removes_its_temp_file_and_keeps_the_old_revision() {
        val store = open()
        store.commit(sampleChange(0))
        var sawTemp = false
        store.beforeCurrentRename = { tmpFile ->
            sawTemp = tmpFile.isFile && tmpFile.name.startsWith(".CURRENT.") && tmpFile.name.endsWith(".tmp")
            throw IOException("rename refused")
        }
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(empty(1)) })
        assertTrue("the temp file existed when the rename failed", sawTemp)
        assertEquals(emptyList<String>(), dir.list()!!.filter { it.endsWith(".tmp") })
        assertEquals("1\n", File(dir, "CURRENT").readText(Charsets.US_ASCII))
        store.beforeCurrentRename = null
        assertEquals(1L, open().load().revision)
    }

    // Matches iOS: a failure of the directory sync after the CURRENT rename is reported, but CURRENT already
    // names the new revision, so the commit did land and a fresh instance reads it.
    @Test fun failed_directory_sync_after_the_current_rename_reports_io_but_the_commit_landed() {
        val store = open(dirSync = { d -> if (d == dir && File(dir, "CURRENT").exists()) throw IOException("x") })
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(sampleChange(0)) })
        assertEquals("1\n", File(dir, "CURRENT").readText(Charsets.US_ASCII))
        assertEquals(emptyList<String>(), dir.list()!!.filter { it.endsWith(".tmp") })
        assertEquals(1L, open().load().revision)
    }

    private class FailingFs(val failOn: (java.nio.file.Path) -> Boolean, val statSaysAbsent: Boolean = false) : StoreFs {
        override fun notExists(p: java.nio.file.Path) = if (failOn(p)) statSaysAbsent else NioStoreFs.notExists(p)
        override fun readAllBytes(p: java.nio.file.Path): ByteArray =
            if (failOn(p)) throw java.nio.file.AccessDeniedException(p.toString()) else NioStoreFs.readAllBytes(p)
        override fun newInputStream(p: java.nio.file.Path): java.io.InputStream =
            if (failOn(p)) throw java.nio.file.AccessDeniedException(p.toString()) else NioStoreFs.newInputStream(p)
    }

    // A stat/read that fails for a reason other than "absent" (EACCES, EIO) must surface, never roll back.
    @Test fun an_unreadable_state_blob_is_an_io_error_never_a_rollback() {
        val store = open()
        store.commit(sampleChange(0))
        store.commit(empty(1))
        store.fs = FailingFs({ it.parent.fileName.toString() == "g2" && it.fileName.toString() == "state.blob" })
        val e = thrown { store.load() }
        assertEquals(LocalStoreException.Kind.IO, e.kind)
        assertEquals("read state.blob", e.detail)
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(empty(2)) })
        assertEquals("2\n", File(dir, "CURRENT").readText(Charsets.US_ASCII))
    }

    @Test fun an_unreadable_current_is_an_io_error_never_an_empty_vault() {
        val store = open()
        store.commit(sampleChange(0))
        store.fs = FailingFs({ it.fileName.toString() == "CURRENT" })
        val e = thrown { store.load() }
        assertEquals(LocalStoreException.Kind.IO, e.kind)
        assertEquals("CURRENT", e.detail)
        assertEquals(LocalStoreException.Kind.IO, kind { store.commit(empty(1)) })
        store.fs = NioStoreFs
        assertEquals(1L, store.load().revision)
    }

    @Test fun a_directory_where_current_should_be_is_an_io_error() {
        val store = open()
        store.commit(sampleChange(0))
        assertTrue(File(dir, "CURRENT").delete())
        assertTrue(File(dir, "g1").deleteRecursively())
        assertEquals(0L, store.load().revision) // genuinely empty
        assertTrue(File(dir, "CURRENT").mkdir())
        assertEquals(LocalStoreException.Kind.IO, kind { store.load() })
    }

    @Test fun a_reentrant_close_inside_a_commit_is_refused_and_the_key_survives() {
        val store = open()
        var refused: Throwable? = null
        store.beforeCurrentWrite = {
            try { store.close() } catch (e: IllegalStateException) { refused = e }
        }
        store.commit(sampleChange(0))
        assertNotNull("close() inside the commit was refused", refused)
        store.beforeCurrentWrite = null
        assertEquals(1L, store.load().revision)
        store.commit(empty(1))
        assertEquals(2L, open().load().revision)
    }

    @Test fun a_plan_hint_failure_does_not_fail_a_durable_commit() {
        val kv = object : KeyValueStore by MemoryStore() {
            override fun remove(key: String, durable: Boolean) = throw IllegalStateException("prefs gone")
        }
        val store = open(AppSettings(kv))
        store.commit(StoreChange(0, mapOf("n0" to note(0)), emptyMap(), null)) // not full: remove() throws
        assertEquals(1L, store.load().revision)
    }

    @Test fun close_waits_for_a_commit_in_flight_and_nothing_is_sealed_with_a_zeroed_key() {
        val store = open()
        store.commit(sampleChange(0))
        val atSeam = CountDownLatch(1)
        val release = CountDownLatch(1)
        store.beforeCurrentWrite = {
            atSeam.countDown()
            release.await(20, TimeUnit.SECONDS)
        }
        val pool = Executors.newFixedThreadPool(2)
        try {
            val commit = pool.submit<String> {
                try { store.commit(StoreChange(1, mapOf("n0" to note(0)), emptyMap(), null)); "ok" } catch (e: LocalStoreException) { e.kind.name }
            }
            assertTrue(atSeam.await(20, TimeUnit.SECONDS))
            val close = pool.submit { store.close() }
            Thread.sleep(300)
            assertFalse("close waits for the commit", close.isDone)
            release.countDown()
            assertEquals("ok", commit.get(20, TimeUnit.SECONDS))
            close.get(20, TimeUnit.SECONDS)
        } finally {
            pool.shutdownNow()
        }
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.commit(empty(2)) })
        val fresh = open().load() // every blob opens with the real key
        assertEquals(2L, fresh.revision)
        assertEquals(setOf("n0"), fresh.records.keys)
    }

    // --- bootstrap (Ruling 9) ------------------------------------------------------------------

    @Test fun store_files_without_their_key_are_reported_not_overwritten() {
        open().commit(sampleChange(0))
        val before = dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).path to it.readBytes().toList() }
        assertEquals(LocalStore.Companion.BootstrapAction.VAULT_WITHOUT_KEY, LocalStore.bootstrap(dir, false))
        val after = dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).path to it.readBytes().toList() }
        assertEquals("nothing is created or changed", before, after)
        assertNotNull(LocalStore.committedRevision(dir))
        assertEquals(LocalStore.Companion.BootstrapAction.OPEN, LocalStore.bootstrap(dir, true))
    }

    @Test fun empty_or_missing_directory_without_a_key_is_a_first_run() {
        assertEquals(LocalStore.Companion.BootstrapAction.FIRST_RUN, LocalStore.bootstrap(dir, false))
        assertFalse("bootstrap creates nothing", dir.exists())
        assertTrue(dir.mkdirs())
        File(dir, ".lock").writeBytes(ByteArray(0)) // a lock file alone holds no vault
        assertEquals(LocalStore.Companion.BootstrapAction.FIRST_RUN, LocalStore.bootstrap(dir, false))
    }

    @Test fun bootstrap_removes_set_aside_copies() {
        open().commit(sampleChange(0))
        LocalStore.setAside(dir, 5)
        assertTrue(File(tmp.root, "Vault-unreadable-5").isDirectory)
        assertEquals(LocalStore.Companion.BootstrapAction.FIRST_RUN, LocalStore.bootstrap(dir, false))
        assertFalse(File(tmp.root, "Vault-unreadable-5").exists())
    }

    // test_extension_store_opens_without_kdf: opening needs only the key; without one it fails and creates nothing.
    @Test fun open_without_a_key_is_no_local_key_and_creates_nothing() {
        open().commit(sampleChange(0))
        val start = System.nanoTime()
        val snap = open().load()
        assertEquals(2, snap.records.size)
        assertTrue("no KDF on the open path", System.nanoTime() - start < 2_000_000_000L)
        val fresh = File(tmp.root, "Fresh")
        val e = thrown { LocalStore.open(fresh, null, FixedRandom(), null) }
        assertEquals(LocalStoreException.Kind.NO_LOCAL_KEY, e.kind)
        assertFalse(fresh.exists())
    }

    @Test fun commit_renames_then_syncs_directories_in_order() {
        val events = mutableListOf<String>()
        val store = open(dirSync = { d ->
            events += "dirsync:" + (if (d == dir) "vault" else "tmp") +
                ":g1=" + File(dir, "g1").exists() + ":current=" + File(dir, "CURRENT").exists()
        })
        store.beforeCurrentWrite = { events += "before-current:g1=" + File(dir, "g1").exists() }
        store.commit(sampleChange(0))
        assertEquals(
            listOf(
                "dirsync:tmp:g1=false:current=false",
                "dirsync:vault:g1=true:current=false",
                "before-current:g1=true",
                "dirsync:vault:g1=true:current=true",
            ),
            events,
        )
    }

    @Test fun stale_commit_reports_expected_and_actual_and_writes_nothing() {
        val store = open()
        store.commit(sampleChange(0))
        val other = open() // a second instance over the same directory
        other.commit(empty(1))
        val e = thrown { store.commit(empty(1)) }
        assertEquals(LocalStoreException.Kind.STALE, e.kind)
        assertEquals("expected 1, actual 2", e.detail)
        assertEquals(2L, store.load().revision)
        assertEquals(listOf("g1", "g2"), gens())
    }

    @Test fun two_instances_committing_at_once_serialise_so_exactly_one_wins() {
        open().commit(empty(0))
        val pool = Executors.newFixedThreadPool(2)
        try {
            val start = CountDownLatch(1)
            val results = (0 until 2).map { i ->
                pool.submit<String> {
                    val store = open()
                    start.await()
                    try {
                        store.commit(StoreChange(1, mapOf("n$i" to note(i)), emptyMap(), null))
                        "ok"
                    } catch (e: LocalStoreException) {
                        e.kind.name
                    }
                }
            }
            start.countDown()
            val got = results.map { it.get(20, TimeUnit.SECONDS) }.sorted()
            assertEquals(listOf("STALE", "ok"), got)
            assertEquals(2L, open().load().revision)
        } finally {
            pool.shutdownNow()
        }
    }

    @Test fun no_lock_is_held_while_the_settings_hint_runs() {
        val other = open()
        var inner: Throwable? = null
        val kv = object : KeyValueStore by MemoryStore() {
            override fun putLong(key: String, value: Long, durable: Boolean) {
                // User code: commits through another instance of the same directory.
                try {
                    other.commit(empty(other.load().revision))
                } catch (t: Throwable) {
                    inner = t
                }
            }
        }
        val store = open(AppSettings(kv))
        store.commit(StoreChange(0, (0 until 4).associate { "n$it" to note(it) }, emptyMap(), null)) // full: hint written
        assertNull(inner?.toString(), inner)
        assertEquals(2L, other.load().revision)
    }

    @Test fun a_failing_settings_write_does_not_fail_a_committed_commit() {
        val kv = object : KeyValueStore by MemoryStore() {
            override fun putLong(key: String, value: Long, durable: Boolean) = throw IllegalStateException("prefs gone")
        }
        val store = open(AppSettings(kv))
        store.commit(StoreChange(0, (0 until 4).associate { "n$it" to note(it) }, emptyMap(), null))
        assertEquals(1L, store.load().revision)
    }

    // Adapts test_nothing_secret_in_user_defaults: only the plan hint reaches settings; no secret is plaintext on disk.
    @Test fun nothing_but_the_plan_hint_reaches_settings_and_no_secret_is_plain_on_disk() {
        val written = mutableListOf<String>()
        val kv = object : KeyValueStore by MemoryStore() {
            override fun putLong(key: String, value: Long, durable: Boolean) { written += key }
            override fun remove(key: String, durable: Boolean) { written += key }
            override fun putString(key: String, value: String, durable: Boolean) { written += key }
            override fun putBoolean(key: String, value: Boolean, durable: Boolean) { written += key }
        }
        val store = open(AppSettings(kv))
        val change = sampleChange(0)
        store.commit(change)
        store.commit(StoreChange(1, (0 until 4).associate { "n$it" to note(it) }, emptyMap(), change.sync))
        assertEquals(setOf(AppSettings.Key.PLAN_FULL_REVISION), written.toSet())
        val signing = change.sync!!.identity.signingPrivateKey
        val needles = listOf(key, signing, change.sync!!.key, Base64Std.encode(signing).toByteArray(), Base64Std.encode(key).toByteArray())
        for (f in dir.walkTopDown().filter { it.isFile }) {
            val bytes = String(f.readBytes(), Charsets.ISO_8859_1)
            for (n in needles) assertFalse(f.name, bytes.contains(String(n, Charsets.ISO_8859_1)))
        }
    }

    @Test fun the_instance_zeroes_its_key_copy_and_refuses_use_after_close() {
        val k = ByteArray(32) { 9 }
        val store = open(k = k)
        k.fill(0) // the caller's array is its own: the store kept a copy
        store.commit(sampleChange(0))
        assertEquals(1L, store.load().revision)
        store.close()
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.load() })
        assertEquals(LocalStoreException.Kind.BAD_LOCAL_KEY, kind { store.commit(empty(1)) })
    }

    @Test fun exception_text_never_carries_item_text() {
        val store = open()
        store.commit(sampleChange(0))
        File(dir, "g1/i0.blob").writeBytes(ByteArray(40))
        val e = thrown { store.load() }
        assertNotNull(e.message)
        assertFalse(e.message!!.contains(secretPassword))
    }
}
