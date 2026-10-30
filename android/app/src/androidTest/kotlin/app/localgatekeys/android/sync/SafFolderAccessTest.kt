package app.localgatekeys.android.sync

import app.localgatekeys.android.i18n.appTxt
import android.net.Uri
import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncIssue
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * [SafFolderAccess] and [SafFolderOpener] over a local document tree served by the test package
 * ([TestDocumentsProvider]: its own process and uid, so the app reaches it only through a real, persistable URI grant,
 * like a cloud app's folder). No real cloud account and none of the person's data is touched.
 */
class SafFolderAccessTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val testPackage = InstrumentationRegistry.getInstrumentation().context.packageName
    private val control = Uri.parse("content://$testPackage.documents.control")
    private val opener = SafFolderOpener(context)
    private lateinit var tree: Uri

    private fun call(method: String, arg: String? = null, data: ByteArray? = null): Bundle =
        context.contentResolver.call(control, method, arg, data?.let { Bundle().apply { putByteArray("data", it) } })!!

    private fun raw(path: String): ByteArray? = call("get", "t1/$path").getByteArray("data")

    private fun rawNames(dir: String): List<String> = call("names", "t1/$dir").getStringArrayList("names")!!

    @Before fun setUp() {
        opener.keepOnly(null)
        tree = Uri.parse(call("reset", "t1").getString("tree"))
        call("grant", tree.toString())
        assertEquals(tree.toString(), opener.persist(tree))
    }

    @After fun tearDown() {
        opener.keepOnly(null)
        runCatching { call("revoke", tree.toString()) }
    }

    private fun access() = opener.open(tree.toString())

    private fun assertNotFound(block: () -> Unit) {
        try {
            block(); fail("expected NOT_FOUND")
        } catch (e: FolderAccessException) {
            assertEquals(e.detail, FolderAccessException.Kind.NOT_FOUND, e.kind)
        }
    }

    private fun assertIo(block: () -> Unit): FolderAccessException {
        try {
            block(); fail("expected IO")
        } catch (e: FolderAccessException) {
            assertEquals(e.detail, FolderAccessException.Kind.IO, e.kind)
            return e
        }
        throw AssertionError()
    }

    @Test fun round_trip_through_the_document_tree() {
        val f = access()
        val path = "${FolderLayout.DEVICES_DIR}/a1.lgksync"
        assertFalse(f.exists(FolderLayout.SYNC_DIR))
        assertNotFound { f.list(FolderLayout.DEVICES_DIR) }
        assertNotFound { f.read(path, 100) }

        val data = ByteArray(70_000) { (it % 251).toByte() } // several read buffers
        f.writeAtomic(path, data) // creates both folders
        assertTrue(f.exists(FolderLayout.SYNC_DIR)); assertTrue(f.exists(FolderLayout.DEVICES_DIR)); assertTrue(f.exists(path))
        assertArrayEquals(data, f.read(path, data.size + 1))
        assertArrayEquals(data.copyOf(10), f.read(path, 10)) // at most `limit` bytes
        assertEquals(0, f.read(path, 0).size)
        assertArrayEquals(data, raw(path)) // really stored in the provider
        assertEquals(listOf("a1.lgksync"), f.list(FolderLayout.DEVICES_DIR))
        assertEquals(listOf("devices"), f.list(FolderLayout.SYNC_DIR))
        assertEquals(listOf("a1.lgksync"), rawNames(FolderLayout.DEVICES_DIR)) // no temp left behind

        f.writeAtomic(FolderLayout.KEYRING_PATH, "{}".toByteArray())
        assertEquals(setOf("devices", "keyring.lgkkeys"), f.list(FolderLayout.SYNC_DIR).toSet())
        assertIo { f.read(FolderLayout.DEVICES_DIR, 10) } // a folder is not a file
        assertIo { f.list(FolderLayout.KEYRING_PATH) }

        f.remove(path)
        assertFalse(f.exists(path)); assertNull(raw(path))
        assertNotFound { f.remove(path) }
        assertEquals(emptyList<String>(), f.list(FolderLayout.DEVICES_DIR))
    }

    @Test fun bad_paths_are_refused_and_never_exist() {
        val f = access()
        for (p in listOf("", "/x", "x/", "a//b", "../x", "a/./b", "LocalGateKeys Sync/..")) {
            assertFalse(p, f.exists(p))
            assertIo { f.read(p, 1) }
            assertIo { f.writeAtomic(p, byteArrayOf(1)) }
        }
        assertEquals(listOf<String>(), rawNames(""))
    }

    /** Android's own storage: a rename to a taken name picks `name (1)`. The old file is rewritten and checked. */
    @Test fun atomic_replace_when_the_provider_renames_to_a_new_name() {
        replaceCase(TestDocumentsProvider.RenameMode.UNIQUIFY)
    }

    /** A provider that renames over an existing file: the rename is the replace. */
    @Test fun atomic_replace_when_the_provider_renames_over_the_file() {
        replaceCase(TestDocumentsProvider.RenameMode.REPLACE)
    }

    /** A provider that cannot rename: the file is created, then rewritten in place, and read back each time. */
    @Test fun replace_falls_back_to_rewrite_and_verify_without_rename() {
        replaceCase(TestDocumentsProvider.RenameMode.UNSUPPORTED)
    }

    private fun replaceCase(mode: TestDocumentsProvider.RenameMode) {
        call("rename", mode.name)
        val f = access()
        val path = "${FolderLayout.DEVICES_DIR}/a1.lgksync"
        val long = ByteArray(5000) { 7 }
        val short = ByteArray(12) { 9 }
        f.writeAtomic(path, long)
        assertArrayEquals(long, raw(path))
        f.writeAtomic(path, short) // shorter: a rewrite must truncate
        assertArrayEquals(short, raw(path))
        assertArrayEquals(short, f.read(path, 10_000))
        f.writeAtomic(path, long)
        assertArrayEquals(long, raw(path))
        // A fresh instance (a new sync run) starts over with the rename and still ends right.
        access().writeAtomic(path, short)
        assertArrayEquals(short, raw(path))
        // Exactly the one file: no temp, no "a1 (1).lgksync" left behind.
        assertEquals(listOf("a1.lgksync"), rawNames(FolderLayout.DEVICES_DIR))
        assertEquals(listOf("a1.lgksync"), f.list(FolderLayout.DEVICES_DIR))
    }

    /**
     * A provider whose renamed document answers no display name: a rename that kept the exact name must count as
     * placed, and the written file must never be deleted as the "temp" (review finding: it was, after a reported success).
     */
    @Test fun a_rename_without_a_display_name_never_deletes_the_written_file() {
        for (mode in listOf(TestDocumentsProvider.RenameMode.REPLACE, TestDocumentsProvider.RenameMode.UNIQUIFY)) {
            call("reset", "t1"); call("grant", tree.toString())
            call("rename", mode.name); call("nullNames", "true")
            val f = access()
            val path = "${FolderLayout.DEVICES_DIR}/a1.lgksync"
            val first = ByteArray(300) { 1 }
            val second = ByteArray(40) { 2 }
            f.writeAtomic(path, first) // no file yet
            assertArrayEquals(mode.name, first, raw(path))
            f.writeAtomic(path, second) // over the existing file
            assertArrayEquals(mode.name, second, raw(path))
            assertArrayEquals(mode.name, second, f.read(path, 1000))
            f.writeAtomic(FolderLayout.KEYRING_PATH, first)
            assertArrayEquals(mode.name, first, raw(FolderLayout.KEYRING_PATH))
            assertEquals(mode.name, listOf("a1.lgksync"), rawNames(FolderLayout.DEVICES_DIR))
            assertEquals(mode.name, listOf("devices", "keyring.lgkkeys"), rawNames(FolderLayout.SYNC_DIR))
        }
    }

    /** A provider that keeps two documents under one name after a rename: the old one is deleted. */
    @Test fun a_duplicate_left_by_the_rename_is_removed() {
        call("rename", TestDocumentsProvider.RenameMode.DUPLICATE.name)
        val f = access()
        val path = "${FolderLayout.DEVICES_DIR}/a1.lgksync"
        f.writeAtomic(path, ByteArray(10) { 1 })
        f.writeAtomic(path, ByteArray(20) { 2 })
        assertEquals(listOf("a1.lgksync"), f.list(FolderLayout.DEVICES_DIR))
        assertArrayEquals(ByteArray(20) { 2 }, f.read(path, 100))
        val onDisk = rawNames(FolderLayout.DEVICES_DIR)
        assertEquals(onDisk.toString(), 1, onDisk.size) // the old document is gone, only the renamed one stays
        assertArrayEquals(ByteArray(20) { 2 }, raw("${FolderLayout.DEVICES_DIR}/${onDisk.single()}"))
    }

    /** Once the provider refused to rename over a file, the next write of that run rewrites without a temp upload. */
    @Test fun known_rewrite_skips_the_temp_but_still_checks_the_bytes() {
        for (mode in listOf(TestDocumentsProvider.RenameMode.UNIQUIFY, TestDocumentsProvider.RenameMode.UNSUPPORTED)) {
            call("reset", "t1"); call("grant", tree.toString()); call("rename", mode.name)
            val f = access()
            val path = "${FolderLayout.DEVICES_DIR}/a1.lgksync"
            f.writeAtomic(path, ByteArray(10) { 1 }) // new file: temp
            f.writeAtomic(path, ByteArray(10) { 2 }) // existing: temp, the rename is refused -> rewrite
            fun temps() = call("created").getStringArrayList("names")!!.count { it.endsWith(".tmp") }
            assertEquals(mode.name, 2, temps())
            f.writeAtomic(path, ByteArray(7) { 3 }) // known: straight rewrite
            assertEquals(mode.name, 2, temps())
            assertArrayEquals(mode.name, ByteArray(7) { 3 }, raw(path))
            assertEquals(mode.name, listOf("a1.lgksync"), rawNames(FolderLayout.DEVICES_DIR))
        }
    }

    @Test fun temp_files_follow_the_core_name_rule_and_are_hidden_from_callers_that_skip_tmp() {
        call("rename", TestDocumentsProvider.RenameMode.UNSUPPORTED.name) // the temp stays until the end of the write
        val f = access()
        f.writeAtomic("${FolderLayout.DEVICES_DIR}/a1.lgksync", byteArrayOf(1, 2, 3))
        val temps = call("created").getStringArrayList("names")!!.filter { it.endsWith(".tmp") }
        assertEquals(1, temps.size)
        assertTrue(temps.single(), Regex("""^\.a1\.lgksync\.[0-9a-f]{16}\.tmp$""").matches(temps.single()))

        // Another device's write in flight: listed (the folder holds it), skipped by the `.*.tmp` rule FolderSync uses.
        call("put", "t1/${FolderLayout.DEVICES_DIR}/.b2.lgksync.0123abcd.tmp", byteArrayOf(4))
        val names = f.list(FolderLayout.DEVICES_DIR)
        assertEquals(setOf("a1.lgksync", ".b2.lgksync.0123abcd.tmp"), names.toSet())
        assertEquals(listOf("a1.lgksync"), names.filterNot { it.startsWith(".") && it.endsWith(".tmp") })
    }

    @Test fun keep_only_releases_every_other_folder_permission() {
        val other = TestDocumentsControl.tree(InstrumentationRegistry.getInstrumentation().context, "t2")
        call("grant", other.toString())
        opener.persist(other)
        assertTrue(opener.isAvailable(tree.toString())); assertTrue(opener.isAvailable(other.toString()))
        opener.keepOnly(tree.toString())
        assertTrue(opener.isAvailable(tree.toString())); assertFalse(opener.isAvailable(other.toString()))
        opener.keepOnly(null)
        assertFalse(opener.isAvailable(tree.toString()))
        assertTrue(context.contentResolver.persistedUriPermissions.isEmpty())
    }

    @Test fun revoked_folder_permission_is_folder_missing() = runBlocking {
        val f = access()
        f.writeAtomic(FolderLayout.KEYRING_PATH, "{}".toByteArray())
        assertTrue(opener.isAvailable(tree.toString()))

        // The permission is taken away (system settings, the provider app cleared or removed).
        call("revoke", tree.toString())
        assertFalse(opener.isAvailable(tree.toString()))
        val e = assertIo { opener.open(tree.toString()) }
        assertEquals("the chosen folder is no longer available", e.detail)
        // A folder opened before the revoke: nothing crashes; exists answers false, the rest is IO.
        assertFalse(f.exists(FolderLayout.SYNC_DIR))
        assertIo { f.list(FolderLayout.SYNC_DIR) }
        assertIo { f.read(FolderLayout.KEYRING_PATH, 10) }
        assertIo { f.writeAtomic(FolderLayout.KEYRING_PATH, byteArrayOf(1)) }
        assertArrayEquals("{}".toByteArray(), raw(FolderLayout.KEYRING_PATH)) // nothing changed in the folder

        // The coordinator's folder run reports folder-missing in the desktop wording and writes nothing.
        val dir = File(context.cacheDir, "saf-revoked").apply { deleteRecursively(); mkdirs() }
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 4 }, SystemRandomSource())
        slots.write(Slot.FOLDER_URI, tree.toString().toByteArray())
        val store = CountingStore()
        val deps = SyncDependencies(
            slots = slots, folders = opener, lan = LanTransporting.UNAVAILABLE, random = SystemRandomSource(),
            clock = SystemClock(), licenseKeys = emptyMap(),
        )
        val report = withContext(Dispatchers.IO) { SyncCoordinator.folderRun(store, deps, slots.installId()) }
        assertEquals(listOf("folder-missing"), report.issues.map { it.kind })
        assertEquals(
            "The sync folder is not available. Check that the cloud app is running and the folder exists.",
            SyncWording(appTxt()).text(SyncIssue("folder-missing")),
        )
        assertEquals(0, store.commits)
        // And the Sync tab asks to choose the folder again.
        val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
        try {
            val c = withContext(Dispatchers.Main) { SyncCoordinator(store, deps, scope, appTxt()) }
            c.refreshMembership()
            assertFalse(c.membership.value.hasFolderUri)
            withContext(Dispatchers.Main) { c.shutdown() }
        } finally {
            scope.cancel()
        }
    }

    /** The desktop vector group's folder, joined with its password through the real opener and coordinator. */
    @Test fun folder_join_through_the_coordinator_writes_this_phone_file() = runBlocking {
        val vectors = InstrumentationRegistry.getInstrumentation().context.assets
        call("put", "t1/${FolderLayout.KEYRING_PATH}", vectors.open("vectors/sync/keyring_epoch1.json").use { it.readBytes() })
        val dir = File(context.cacheDir, "saf-join").apply { deleteRecursively(); mkdirs() }
        val slots = SecretSlots(File(dir, "secrets.bin"), ByteArray(32) { 6 }, SystemRandomSource())
        val store = MemStore()
        val deps = SyncDependencies(
            slots = slots, folders = opener, lan = LanTransporting.UNAVAILABLE, random = SystemRandomSource(),
            clock = object : app.localgatekeys.core.primitives.UnixClock { override val now = 1_790_001_000L },
            licenseKeys = emptyMap(),
        )
        val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
        try {
            val c = withContext(Dispatchers.Main) { SyncCoordinator(store, deps, scope, appTxt()) }
            assertTrue(c.actionError.value ?: "", c.joinFolder(tree.toString(), "correct horse battery staple 42"))
            val state = store.snapshot.sync!!
            assertTrue(state.hasFolder)
            assertEquals(tree.toString(), slots.read(Slot.FOLDER_URI)!!.toString(Charsets.UTF_8))
            assertNotNull(raw("${FolderLayout.DEVICES_DIR}/${state.deviceId}.lgksync"))
            assertEquals(listOf("${state.deviceId}.lgksync"), rawNames(FolderLayout.DEVICES_DIR)) // no temp left
            assertTrue(opener.isAvailable(tree.toString())) // the joined folder keeps its permission
            c.refreshMembership()
            assertTrue(c.membership.value.hasFolderUri)
            // The next run reads and rewrites through the same tree.
            c.sync(SyncCoordinator.Trigger.MANUAL)
            assertTrue(c.issues.value.map { it.kind }.toString(), c.issues.value.none { it.severity == SyncWording.Severity.ERROR })
            // Leaving gives the folder's permission up.
            c.leave()
            assertFalse(opener.isAvailable(tree.toString()))
            assertTrue(context.contentResolver.persistedUriPermissions.isEmpty())
            withContext(Dispatchers.Main) { c.shutdown() }
        } finally {
            scope.cancel()
        }
    }

    private class MemStore : ItemStore {
        @Volatile var snapshot = StoreSnapshot()
        override fun load() = snapshot
        @Synchronized override fun commit(change: StoreChange) {
            snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        }
    }

    private class CountingStore : ItemStore {
        @Volatile var commits = 0
        override fun load() = StoreSnapshot()
        override fun commit(change: StoreChange) { commits++ }
    }

    @Test fun persist_without_a_grant_fails() {
        val ungranted = TestDocumentsControl.tree(InstrumentationRegistry.getInstrumentation().context, "never-granted")
        assertIo { opener.persist(ungranted) }
        assertFalse(opener.isAvailable(ungranted.toString()))
        assertNotNull(opener.open(tree.toString()))
    }
}
