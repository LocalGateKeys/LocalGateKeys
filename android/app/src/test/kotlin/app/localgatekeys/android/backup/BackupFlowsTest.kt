package app.localgatekeys.android.backup

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.syncState
import app.localgatekeys.android.sync.GatedStore
import app.localgatekeys.android.sync.LockedStore
import app.localgatekeys.android.sync.SessionGate
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreSnapshot
import java.time.ZoneOffset
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupFlowsTest {
    private val txt = EnglishTxt()
    private val text = BackupText(txt)

    private val now = 1_800_000_000L
    private val good = "correct horse battery staple 42"

    /** A real (cheap-KDF) file of three notes made on another phone. */
    private fun file(): ByteArray {
        val states = (1..3).map { live(noteRecord(noteId(it), "Note $it", 1_799_000_000L + it), mapOf(OTHER_PHONE to 1L)) }
        return PhoneBackupFormat.write(states, good, OTHER_PHONE, "android", "1.0.0", now, false, CountingRandom(), TEST_KDF)
    }

    private fun flow(store: ItemStore, attempts: RestoreAttempts = RestoreAttempts(TestClock(now))) =
        RestoreFlow(attempts, { PhoneRestore(store, { false }, TestClock(now), installId = { INSTALL_ID }) }, Dispatchers.Unconfined, txt)

    @Test fun five_wrong_passwords_then_thirty_seconds() = runBlocking {
        val clock = TestClock(now)
        val attempts = RestoreAttempts(clock)
        val store = CountingStore()
        val f = flow(store, attempts)
        f.chose(file())
        assertEquals(RestoreFlow.Step.PASSWORD, f.step.value)
        assertEquals("Made on an Android phone on 2027-01-15.", f.from.value)
        repeat(5) {
            assertFalse(attempts.blocked())
            f.updatePassword("wrong"); f.open()
            assertEquals("Wrong password, or the file is damaged.", f.error.value)
            assertEquals("the typed password is cleared once tried", "", f.password.value)
        }
        assertTrue(attempts.blocked())
        f.updatePassword(good); f.open()
        assertEquals(text.tooManyAttempts, f.error.value)
        assertEquals(RestoreFlow.Step.PASSWORD, f.step.value)
        clock.now += 29
        assertTrue(attempts.blocked())
        clock.now += 1
        assertFalse(attempts.blocked())
        f.updatePassword(good); f.open()
        assertNull(f.error.value)
        assertEquals(RestoreFlow.Step.PREVIEW, f.step.value)
        assertEquals(listOf("3 new items", "0 items updated from the backup", "0 already up to date"), f.lines.value)
        assertEquals(text.previewReady, f.status.value)
        assertEquals("the preview writes nothing", 0, store.commits)
        assertTrue(f.restore())
        assertEquals(RestoreFlow.Step.DONE, f.step.value)
        assertEquals(listOf("3 new items", "0 items updated from the backup"), f.lines.value)
        assertEquals("Phone backup restored.", f.status.value)
        assertEquals(1, store.commits)
        assertFalse("toString shows no password or states", f.toString().contains(good))
    }

    @Test fun a_success_resets_the_wrong_password_count() {
        val attempts = RestoreAttempts(TestClock(now))
        repeat(4) { attempts.wrongPassword() }
        attempts.succeeded()
        repeat(4) { attempts.wrongPassword() }
        assertFalse(attempts.blocked())
        attempts.wrongPassword()
        assertTrue(attempts.blocked())
    }

    @Test fun files_that_are_not_backups_are_refused_before_any_password() {
        val f = flow(CountingStore())
        f.chose("hello".toByteArray())
        assertEquals("This is not a LocalGateKeys phone backup.", f.error.value)
        assertEquals(RestoreFlow.Step.CHOOSE, f.step.value)
        f.chose(null)
        assertEquals(text.readFailed, f.error.value)
    }

    @Test fun a_backup_of_this_phone_says_so() = runBlocking {
        val store = CountingStore(StoreSnapshot(sync = syncState(OTHER_PHONE)))
        val f = flow(store)
        f.chose(file())
        f.updatePassword(good); f.open()
        assertEquals("This backup was made on this phone, so there is nothing to restore.", f.error.value)
        assertEquals(RestoreFlow.Step.PASSWORD, f.step.value)
    }

    @Test fun lock_during_the_restore_step_writes_nothing() = runBlocking {
        val gate = SessionGate()
        val base = LockedStore(StoreSnapshot(sync = syncState()))
        val f = flow(GatedStore(base, gate))
        f.chose(file())
        f.updatePassword(good); f.open()
        assertEquals(RestoreFlow.Step.PREVIEW, f.step.value)
        gate.close()
        assertFalse(f.restore())
        assertEquals(0, base.commits)
        assertEquals(RestoreFlow.Step.PREVIEW, f.step.value)
    }

    /** Ruling 26: the desktop's check_sync_password over the port of its estimate_strength. */
    @Test fun backup_password_check_follows_the_desktop_sync_password_rule() {
        assertEquals("Use at least 12 characters.", BackupPasswordCheck.problem("short", "short", txt))
        assertEquals("Too easy to guess. Add more words or characters.", BackupPasswordCheck.problem("aaaaaaaaaaaa", "aaaaaaaaaaaa", txt))
        // The review's examples: twelve characters and every character class, yet a common password plus a year or digits.
        for (weak in listOf("Password123!", "P@ssw0rd2026", "Qwerty123456!")) {
            val r = BackupPasswordCheck.check(weak, weak, txt)
            assertFalse(weak, r.ok)
            assertEquals(1, r.score)
            assertEquals("Weak", r.label)
            assertEquals("Too easy to guess. Add more words or characters.", r.message)
        }
        // Lower case only, no word or pattern: the desktop rates it 4.
        val random = BackupPasswordCheck.check("qwxzvbnmlkjh", "qwxzvbnmlkjh", txt)
        assertTrue(random.ok); assertEquals(4, random.score); assertEquals("Very strong", random.label); assertEquals("Good.", random.message)
        assertEquals("The two passwords do not match.", BackupPasswordCheck.problem(good, "other", txt))
        assertNull(BackupPasswordCheck.problem(good, good, txt))
        assertEquals(BackupPasswordCheck.Result(false, 0, "Very weak", "Use at least 12 characters."), BackupPasswordCheck.check("", "", txt))
    }

    @Test fun export_flow_checks_then_exports_and_forgets_the_password() = runBlocking {
        val seen = ArrayList<String>()
        val f = ExportFlow({ pw -> seen.add(pw); BackupExport(byteArrayOf(1, 2, 3)) }, Dispatchers.Unconfined, txt)
        assertNull(f.strengthText())
        f.updatePassword("Password123!")
        assertEquals("Strength: Weak", f.strengthText())
        f.updatePassword(good); f.updateConfirm("nope")
        assertEquals("Strength: Very strong", f.strengthText())
        assertNull(f.make())
        assertEquals("The two passwords do not match.", f.message.value)
        assertTrue(seen.isEmpty())
        f.updateConfirm(good)
        assertTrue(f.make()!!.contentEquals(byteArrayOf(1, 2, 3)))
        assertEquals(listOf(good), seen)
        assertEquals("", f.password.value); assertEquals("", f.confirm.value)
        assertFalse(f.toString().contains(good))
        f.written(true)
        assertEquals(text.saved, f.message.value)
        f.written(false)
        assertEquals(text.writeFailed, f.message.value)
        // A failing export says so and keeps nothing.
        val broken = ExportFlow({ throw IllegalStateException("locked") }, Dispatchers.Unconfined, txt)
        broken.updatePassword(good); broken.updateConfirm(good)
        assertNull(broken.make())
        assertEquals(text.exportFailed, broken.message.value)
    }

    @Test fun the_password_check_runs_on_the_background_dispatcher() = runBlocking {
        val pool = java.util.concurrent.Executors.newSingleThreadExecutor { r -> Thread(r, "export-io") }
        val io = pool.asCoroutineDispatcher()
        val seen = ArrayList<String>()
        var workingDuringCheck = false
        lateinit var f: ExportFlow
        f = ExportFlow({ BackupExport(byteArrayOf(1)) }, io, txt, check = { p, c ->
            seen += Thread.currentThread().name.substringBefore(" @")
            workingDuringCheck = f.working.value
            BackupPasswordCheck.problem(p, c, txt)
        })
        f.updatePassword("Password123!"); f.updateConfirm("Password123!")
        assertNull(f.make())
        assertEquals("Too easy to guess. Add more words or characters.", f.message.value)
        assertEquals(listOf("export-io"), seen)
        assertTrue("the screen shows the work before the check starts", workingDuringCheck)
        assertFalse(f.working.value)
        pool.shutdown()
    }

    /** The file name and the exported bytes are never translated: only the on-screen texts follow the language. */
    @Test fun written_content_stays_english_under_another_language() = runBlocking {
        val german = object : app.localgatekeys.android.i18n.Txt {
            override fun s(id: Int, vararg args: Any) = "DE:" + txt.s(id, *args)
            override fun plural(id: Int, count: Int, vararg args: Any) = "DE:" + txt.plural(id, count, *args)
        }
        assertEquals("DE:Backup saved.", BackupText(german).saved)
        assertEquals("LocalGateKeys-Backup-2027-01-15.lgkm", BackupText.fileName(now, ZoneOffset.UTC))
        val written = byteArrayOf(9, 8, 7)
        val f = ExportFlow({ BackupExport(written) }, Dispatchers.Unconfined, german, check = { _, _ -> null })
        f.updatePassword("x"); f.updateConfirm("x")
        assertEquals(written.toList(), f.make()!!.toList())
        f.written(true)
        assertEquals("DE:Backup saved.", f.message.value)
    }

    @Test fun file_name_and_result_wording() {
        assertEquals("LocalGateKeys-Backup-2027-01-15.lgkm", BackupText.fileName(now, ZoneOffset.UTC))
        val report = RestoreReport(new = 2, updated = 1, heldBack = 3, skipped = 1, deleted = 1)
        assertEquals(
            listOf("2 new items", "1 item updated from the backup", "1 item deleted (deleted before the backup was made)",
                "3 items held back by the free plan's 4-item limit"),
            text.reportLines(report),
        )
        assertEquals("Phone backup restored. 1 item this version cannot read was skipped.", text.reportStatus(report))
        assertEquals(
            "Phone backup restored. Your Pro licence was restored. Restore again to bring back the 3 held-back items.",
            text.reportStatus(RestoreReport(new = 1, heldBack = 3, licenseRestored = true)),
        )
        assertEquals("Nothing was restored: 2 items this version cannot read were skipped.", text.reportStatus(RestoreReport(skipped = 2)))
        assertEquals("Nothing was restored: the vault changed while restoring. Try again.", text.reportStatus(RestoreReport(failure = "busy")))
        assertEquals("Nothing was restored: the vault could not be updated.", text.reportStatus(RestoreReport(failure = "apply-failed")))
    }
}
