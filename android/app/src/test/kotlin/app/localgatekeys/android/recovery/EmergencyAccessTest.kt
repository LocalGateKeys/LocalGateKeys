package app.localgatekeys.android.recovery

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.recovery.HeirException
import app.localgatekeys.core.recovery.HeirFlowException
import app.localgatekeys.core.recovery.HeirFolder
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Emergency access on the phone over the desktop's files (tests/vectors/heir/v1.json). */
class EmergencyAccessTest {
    private val v: Map<String, JsonValue> = run {
        val repo = System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set")
        (CanonicalJson.parse(File(repo, "tests/vectors/heir/v1.json").readBytes()) as JsonValue.Obj).fields
    }
    private val packages = v.getValue("packages").arr().map { it.str().toByteArray(Charsets.UTF_8) }
    private val planId = v.getValue("plan_id").str()
    private val dir = "LocalGateKeys Emergency/$planId"

    private class MemStore(var snap: StoreSnapshot = StoreSnapshot()) : ItemStore {
        override fun load() = snap
        override fun commit(change: StoreChange) {
            check(change.baseRevision == snap.revision)
            snap = StoreSnapshot(change.records, change.meta, change.sync, snap.revision + 1)
        }
    }

    private class MemFolder : FolderAccess {
        val files = LinkedHashMap<String, ByteArray>()
        override fun list(dir: String): List<String> {
            val names = files.keys.filter { it.startsWith("$dir/") }.map { it.removePrefix("$dir/") }.filter { "/" !in it }
            if (names.isEmpty()) throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, dir)
            return names
        }
        override fun read(path: String, limit: Int): ByteArray =
            (files[path] ?: throw FolderAccessException(FolderAccessException.Kind.NOT_FOUND, path)).let { it.copyOf(minOf(limit, it.size)) }
        var failWrites = false
        override fun writeAtomic(path: String, data: ByteArray) {
            if (failWrites) throw FolderAccessException(FolderAccessException.Kind.IO, path)
            files[path] = data.copyOf()
        }
        override fun remove(path: String) { files.remove(path) }
        override fun exists(path: String) = files.keys.any { it == path || it.startsWith("$path/") }
    }

    private lateinit var clock: TestClock
    private lateinit var folder: MemFolder
    private lateinit var store: MemStore
    private var edits = 0

    private fun access(slots: SecretSlots) = EmergencyAccess(
        store, slots, openFolder = { uri -> if (uri == "content://heir") HeirFolder(folder) else null }, clock = clock,
        random = SystemRandomSource(), onLocalEdit = { edits++ },
    )

    private fun slots() = SecretSlots(File(tempDir("heir-slots"), "secrets.bin"), ByteArray(32) { 4 }, SystemRandomSource())

    private fun thrown(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        fail("expected an exception"); throw AssertionError()
    }

    @Before fun setUp() {
        clock = TestClock(v.getValue("created").long() + 100)
        folder = MemFolder()
        store = MemStore()
    }

    private fun withPlan() {
        val wrapper = v.getValue("wrapper")
        store.snap = StoreSnapshot(mapOf("heir:plan" to wrapper), mapOf("heir:plan" to SyncMeta.live(wrapper, mapOf("desktop-a" to 1L))))
    }

    @Test fun the_owner_phone_lists_denies_and_the_refusal_is_kept_in_the_plan() {
        withPlan()
        val a = access(slots())
        assertEquals(listOf("Νίκος", "Anna", "Ben"), a.plan()!!.holders)
        assertEquals("no-folder", (thrown { a.pending() } as HeirFlowException).reason)
        a.setFolder("content://heir")
        val r = v.getValue("request").obj().fields
        folder.files["$dir/${r.getValue("file").str()}"] = r.getValue("data").str().toByteArray(Charsets.UTF_8)
        clock.now = r.getValue("created").long()
        val listed = a.pending().requests.single()
        assertEquals("Anna", listed.holder)
        val notices = HeirNotices()
        assertEquals(listOf("Anna asked for emergency access to your vault. Days left to deny it: 7."), notices.check(a, EnglishTxt()))
        assertTrue(notices.check(a, EnglishTxt()).isEmpty())
        a.deny(listed.requestId)
        assertEquals(1, edits)
        assertTrue(folder.files.keys.any { it.startsWith("$dir/deny-${listed.requestId}") })
        val denied = (a.planRecord()!!.fields.getValue("denied") as JsonValue.Arr).items.map { it.str() }
        assertTrue(listed.requestId in denied)
        assertTrue(a.pending().requests.isEmpty())
    }

    @Test fun a_deny_is_kept_in_the_plan_first_even_when_the_folder_write_fails() {
        withPlan()
        val a = access(slots())
        a.setFolder("content://heir")
        val r = v.getValue("request").obj().fields
        folder.files["$dir/${r.getValue("file").str()}"] = r.getValue("data").str().toByteArray(Charsets.UTF_8)
        clock.now = r.getValue("created").long()
        val listed = a.pending().requests.single()
        folder.failWrites = true
        thrown { a.deny(listed.requestId) }
        // The refusal is recorded (and syncs), so another owner device writes the deny file again.
        val denied = (a.planRecord()!!.fields.getValue("denied") as JsonValue.Arr).items.map { it.str() }
        assertTrue(listed.requestId in denied)
        assertEquals(1, edits)
        folder.failWrites = false
        a.pending()
        assertTrue(folder.files.keys.any { it.startsWith("$dir/deny-${listed.requestId}") })
    }

    @Test fun the_holder_phone_asks_follows_the_status_and_recovers_the_phrase() {
        val a = access(slots())
        a.setFolder("content://heir")
        assertEquals("Νίκος", a.addPackage(packages[0]).holder)
        assertEquals("duplicate", (thrown { a.addPackage(packages[0]) } as HeirException).reason)
        assertEquals("malformed", (thrown { a.addText("lgkheir:abc") } as HeirException).reason)
        assertEquals("Ben", a.addText(v.getValue("qr").arr()[2].str()).holder)
        assertEquals(2, a.shards().size)
        assertEquals("none", a.status().state)
        a.request()
        assertEquals("waiting", a.status().state)
        assertEquals("waiting", (thrown { a.recoverPhrase() } as HeirFlowException).reason)
        clock.now += 7 * 86_400
        assertEquals("no-backup", a.status().state)
        // Without a backup newer than the plan nothing is revealed, and the status says why (not "ready").
        assertEquals("no-backup", (thrown { a.recoverPhrase() } as HeirFlowException).reason)
        assertEquals(EnglishTxt().s(app.localgatekeys.android.R.string.heir_state_no_backup), EmergencyAccess.statusText(a.status(), EnglishTxt()))
        val d = v.getValue("descriptor").obj().fields
        folder.files["$dir/${d.getValue("file").str()}"] = d.getValue("data").str().toByteArray(Charsets.UTF_8)
        assertEquals("ready", a.status().state)
        assertEquals(v.getValue("phrase").str(), a.recoverPhrase())
        // The same keys next time (kept in the vault's slots), so the request stays this phone's.
        assertEquals("ready", a.status().state)
        a.clearShards()
        assertTrue(a.packages().isEmpty())
        assertFalse(a.shards().isNotEmpty())
    }

    @Test fun messages_are_in_words() {
        val t = EnglishTxt()
        assertEquals("The owner denied this request.", EmergencyAccess.message(HeirFlowException("denied"), t))
        assertEquals("The waiting period is not over. Days left: 3.", EmergencyAccess.message(HeirFlowException("waiting", daysLeft = 3), t))
        assertEquals("This is not the recovery phrase the plan was made from.", EmergencyAccess.message(HeirFlowException("wrong-phrase"), t))
    }
}
