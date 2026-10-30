package app.localgatekeys.android.backup

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.attachments.DocumentStore
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.sync.LockedStore
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.sync.DirectoryAttachmentVault
import app.localgatekeys.core.sync.Documents
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Phone backup format 2 on the phone: document files go into the backup and come back on restore. */
class BackupFilesTest {
    private val txt = EnglishTxt()
    private val text = BackupText(txt)

    @get:Rule val tmp = TemporaryFolder()

    private val now = 1_800_000_000L
    private val password = "correct horse battery staple 42"

    private class Source(val store: LockedStore, val vault: DirectoryAttachmentVault, val docId: String, val noteId: String)

    /** A phone with one document and one note. */
    private fun source(): Source {
        val store = LockedStore()
        val vault = DirectoryAttachmentVault(File(tmp.root, "src-att"))
        val docs = DocumentStore(store, vault, SystemRandomSource(), TestClock(now))
        val (_, id) = docs.add("synthetic scan\n".toByteArray(), "scan.pdf", "application/pdf", "", true)
        val note = noteRecord(noteId(1), "A note", 1_799_000_000)
        val snap = store.load()
        store.commit(
            app.localgatekeys.core.sync.StoreChange(snap.revision, snap.records + (noteId(1) to wrap(note)), snap.meta, snap.sync),
        )
        return Source(store, vault, id!!, noteId(1))
    }

    private fun exporter(src: Source, withFiles: Boolean = true) = BackupExporter(
        src.store, TestClock(now), CountingRandom(), "1.0.0", installId = { "fedcba9876543210fedcba9876543210" }, isPro = { true },
        kdf = TEST_KDF, attachments = if (withFiles) src.vault else null,
    )

    private fun restorer(store: CountingStore, vault: DirectoryAttachmentVault?) =
        PhoneRestore(store, { true }, TestClock(now), installId = { INSTALL_ID }, attachments = vault)

    private fun read(bytes: ByteArray): PhoneBackup = PhoneBackupFormat.read(bytes, password)

    @Test fun export_carries_the_document_file_as_format_2() {
        val src = source()
        val made = exporter(src).exportWithFiles(password)
        assertEquals(1, made.filesIncluded); assertEquals(0, made.filesLeftOut)
        val backup = read(made.bytes)
        assertEquals(2, backup.header.version)
        val ref = Documents.refs(backup.states).single()
        assertEquals(setOf(ref.blob), backup.files.keys)
        // Without the attachment store, or with the file missing, it is a format-1 file and the export says so.
        assertEquals(1, read(exporter(src, withFiles = false).export(password)).header.version)
        src.vault.remove(ref)
        val missing = exporter(src).exportWithFiles(password)
        assertEquals(0, missing.filesIncluded); assertEquals(1, missing.filesLeftOut)
        val v1 = read(missing.bytes)
        assertEquals(1, v1.header.version)
        assertTrue("the document stays in the backup", v1.states.any { it.itemId == src.docId })
    }

    @Test fun restore_stores_the_file_then_the_document_and_the_preview_stores_nothing() {
        val src = source()
        val backup = read(exporter(src).export(password))
        val ref = Documents.refs(backup.states).single()
        val store = CountingStore()
        val vault = DirectoryAttachmentVault(File(tmp.root, "dst"))
        val plan = restorer(store, vault).plan(backup)
        assertEquals(1, plan.filesFromBackup); assertEquals(0, plan.filesMissing); assertEquals(2, plan.new)
        assertFalse("the preview stores nothing", vault.has(ref))
        assertEquals(0, store.commits)
        assertTrue(text.planLines(plan).contains("1 document file from the backup"))
        val report = restorer(store, vault).restore(plan)
        assertNull(report.failure)
        assertEquals(1, report.files); assertEquals(0, report.filesRefused); assertEquals(2, report.new)
        assertTrue(vault.has(ref))
        assertNotNull(store.snapshot.records[src.docId])
        assertTrue(text.reportLines(report).contains("1 document file restored"))
    }

    @Test fun a_document_whose_file_is_nowhere_is_left_out_and_counted() {
        val src = source()
        val backup = read(exporter(src, withFiles = false).export(password))
        val store = CountingStore()
        val vault = DirectoryAttachmentVault(File(tmp.root, "dst"))
        val plan = restorer(store, vault).plan(backup)
        assertEquals(1, plan.filesMissing); assertEquals(0, plan.filesFromBackup); assertEquals(1, plan.new)
        assertTrue(text.planLines(plan).contains("1 document will not be restored: its file is not in this backup"))
        val report = restorer(store, vault).restore(plan)
        assertEquals(1, report.filesMissing); assertEquals(1, report.new)
        assertNull(store.snapshot.records[src.docId])
        assertNotNull(store.snapshot.records[src.noteId])
    }

    @Test fun a_file_already_on_this_phone_restores_the_document_without_the_backup_carrying_it() {
        val src = source()
        val withFile = read(exporter(src).export(password))
        val ref = Documents.refs(withFile.states).single()
        val vault = DirectoryAttachmentVault(File(tmp.root, "dst"))
        vault.store(ref, withFile.files.getValue(ref.blob))
        val backup = read(exporter(src, withFiles = false).export(password))
        val store = CountingStore()
        val plan = restorer(store, vault).plan(backup)
        assertEquals(0, plan.filesMissing); assertEquals(0, plan.filesFromBackup)
        val report = restorer(store, vault).restore(plan)
        assertNull(report.failure)
        assertNotNull(store.snapshot.records[src.docId])
    }

    @Test fun a_damaged_file_stores_nothing_and_its_document_is_not_restored() {
        val src = source()
        val good = read(exporter(src).export(password))
        val ref = Documents.refs(good.states).single()
        val damaged = good.files.getValue(ref.blob).copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val backup = good.copy(files = mapOf(ref.blob to damaged))
        val store = CountingStore()
        val vault = DirectoryAttachmentVault(File(tmp.root, "dst"))
        val plan = restorer(store, vault).plan(backup)
        val report = restorer(store, vault).restore(plan)
        assertNull(report.failure)
        assertEquals(0, report.files); assertEquals(1, report.filesRefused)
        assertFalse(vault.has(ref))
        assertNull(store.snapshot.records[src.docId])
        assertNotNull(store.snapshot.records[src.noteId])
        assertTrue(text.reportLines(report).contains("1 document file was damaged and not restored"))
    }

    @Test fun export_flow_says_how_many_files_were_left_out() = kotlinx.coroutines.runBlocking {
        val f = ExportFlow({ BackupExport(byteArrayOf(1), 0, 2) }, kotlinx.coroutines.Dispatchers.Unconfined, txt, check = { _, _ -> null })
        f.updatePassword("x"); f.updateConfirm("x")
        assertNotNull(f.make())
        f.written(true)
        assertEquals(text.saved + " " + text.leftOutLine(2), f.message.value)
    }
}
