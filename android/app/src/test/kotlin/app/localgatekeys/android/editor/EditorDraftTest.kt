package app.localgatekeys.android.editor

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.RecordingVaultKey
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultEraser
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.primitives.SystemRandomSource
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class EditorDraftTest {
    private lateinit var dir: File
    private lateinit var file: File
    private val key = ByteArray(32) { (it + 7).toByte() }
    private val clock = TestClock(NOW)

    @Before fun setUp() {
        dir = tempDir("draft")
        file = EditorDraftStore.file(dir)
    }

    private fun store(k: ByteArray = key) = EditorDraftStore(file, k, SystemRandomSource(), clock)
    private val secret = "hunter2-very-secret-PASSWORD"
    private fun draft(id: String? = null, hash: String? = null) =
        EditorDraft(EditorKind.WEB, id, hash, mapOf("label" to "Bank", "username" to "ann", "password" to secret), NOW)

    @Test fun round_trip() {
        assertTrue(store().save(draft()))
        assertEquals(draft(), store().load())
    }

    @Test fun ciphertext_has_no_plaintext_bytes() {
        store().save(draft())
        val bytes = file.readBytes()
        for (needle in listOf(secret, "Bank", "ann", "password", "web", "lgk-editor-draft-v1")) {
            val n = needle.toByteArray(Charsets.UTF_8)
            val found = (0..bytes.size - n.size).any { i -> n.indices.all { bytes[i + it] == n[it] } }
            assertFalse("plaintext '$needle' in the file", found)
        }
    }

    @Test fun fresh_nonce_each_save() {
        store().save(draft()); val a = file.readBytes()
        store().save(draft()); val b = file.readBytes()
        assertFalse(a.copyOfRange(0, 12).contentEquals(b.copyOfRange(0, 12)))
    }

    @Test fun expires_after_seven_days() {
        store().save(draft())
        clock.now = NOW + EditorDraftStore.MAX_AGE_SECONDS - 1
        assertNotNull(store().load())
        clock.now = NOW + EditorDraftStore.MAX_AGE_SECONDS + 1
        assertNull(store().load())
        assertFalse("an expired draft is deleted", file.exists())
    }

    @Test fun wrong_key_deletes_the_draft() {
        store().save(draft())
        assertNull(store(ByteArray(32) { 9 }).load())
        assertFalse(file.exists())
    }

    @Test fun garbage_file_is_deleted() {
        file.writeBytes(ByteArray(40) { 1 })
        assertNull(store().load())
        assertFalse(file.exists())
    }

    @Test fun zeroed_key_after_lock_writes_and_reads_nothing() {
        store().save(draft())
        val locked = ByteArray(32)
        assertFalse(store(locked).save(draft()))
        assertNull(store(locked).load())
        assertTrue("a locked read leaves the draft for the next unlock", file.exists())
    }

    @Test fun one_draft_only() {
        store().save(draft())
        store().save(EditorDraft(EditorKind.NOTE, null, null, mapOf("title" to "Second"), NOW))
        assertEquals(listOf(EditorDraftStore.FILE_NAME), dir.list()!!.toList())
        assertEquals(EditorKind.NOTE, store().load()!!.kind)
    }

    @Test fun delete_removes_it() {
        store().save(draft())
        store().delete()
        assertFalse(file.exists())
        assertNull(store().load())
    }

    @Test fun erase_deletes_the_draft() = runBlocking {
        store().save(draft())
        val base = tempDir("erase-draft")
        VaultEraser(VaultDirs.under(base), RecordingVaultKey(), AppSettings(MemoryStore()), draftFile = file).erase()
        assertFalse(file.exists())
    }

    @Test fun status_notices_a_changed_or_deleted_item() {
        val store = CountingStore()
        val item = VaultItem.of("0c000000-0000-4000-8000-000000000001", validCard)!!
        val m = EditorModel(store, item, EditorKind.CARD, { false }, clock, CountingRandomForDraft(), EnglishTxt())
        m.set("title", "Changed title")
        val d = m.draft(NOW)
        assertEquals(item.id, d.itemId)
        assertEquals(EditorDraft.Status.SAME_ITEM, d.status(listOf(item)))
        assertEquals(EditorDraft.Status.ITEM_DELETED, d.status(emptyList()))
        val changed = VaultItem.of(item.id, app.localgatekeys.core.json.JsonValue.Obj(validCard.fields + ("title" to app.localgatekeys.core.json.JsonValue.Str("Synced"))))!!
        assertEquals(EditorDraft.Status.ITEM_CHANGED, d.status(listOf(changed)))
        assertEquals(EditorDraft.Status.NEW_ITEM, draft().status(listOf(item)))
    }

    @Test fun restored_values_open_in_the_editor() {
        val m = EditorModel(CountingStore(), null, EditorKind.WEB, { false }, clock, CountingRandomForDraft(), EnglishTxt(), initialValues = draft().values)
        assertEquals(secret, m.value("password"))
        assertTrue("toString never shows values", !m.draft(NOW).toString().contains(secret))
    }
}

private class CountingRandomForDraft : app.localgatekeys.core.primitives.RandomSource {
    private var n = 0
    override fun bytes(count: Int): ByteArray = ByteArray(count) { (n++ and 0xff).toByte() }
}
