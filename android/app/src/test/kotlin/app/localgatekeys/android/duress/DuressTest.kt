package app.localgatekeys.android.duress

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.AppPasswordController
import app.localgatekeys.android.unlock.Authenticator
import app.localgatekeys.android.unlock.RecordingVaultKey
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.unlock.UnlockCredential
import app.localgatekeys.android.unlock.UnlockedVault
import app.localgatekeys.android.unlock.VaultDirs
import app.localgatekeys.android.unlock.VaultOpener
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.AppPasswordAttempts
import app.localgatekeys.android.vault.AppPasswordFiles
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.AppPasswordRequiredException
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.Argon2id
import app.localgatekeys.core.crypto.BouncyCastleArgon2id
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** The duress password on phones (sub-plan 08, Task 5a; desktop tests/test_duress.py and test_controller_unlock.py). */
class DuressTest {
    private lateinit var base: File
    private lateinit var dirs: VaultDirs
    private lateinit var settings: AppSettings
    private lateinit var clock: TestClock
    private lateinit var lock: AppPasswordLock
    private lateinit var duress: DuressVault
    private val random = SystemRandomSource()
    private val cheap = AppPasswordParams(memoryKiB = 8192, iterations = 1, parallelism = 1)
    private val derivations = AtomicInteger()
    private val counting = object : Argon2id {
        private val inner = BouncyCastleArgon2id()
        override fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray {
            derivations.incrementAndGet()
            return inner.derive(password, salt, memoryKiB, iterations, parallelism, length)
        }
    }
    private val authenticator = object : Authenticator {
        override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? = cipher
        override fun cancel() {}
    }
    private val real = "river otter lantern 42"
    private val second = "copper meadow falcon 7"
    private lateinit var systemKey: RecordingVaultKey

    @Before fun setUp() {
        base = tempDir("duress")
        dirs = VaultDirs.under(base)
        settings = AppSettings(MemoryStore())
        clock = TestClock(1_800_000_000)
        systemKey = RecordingVaultKey()
        lock = AppPasswordLock(AppPasswordFiles.under(base), FakeVaultKey(), random, AppPasswordAttempts.of(settings), clock, { counting }, BootClock.NONE)
        duress = DuressVault(DuressFiles.under(base), random, clock, { counting }, cheap)
    }

    private fun pw(s: String) = AppPasswordRecord.passwordBytes(s)

    private fun opener() = VaultOpener(dirs, systemKey, random, null, cryptoBound = true, appPassword = lock, duress = duress)

    private fun open(credential: UnlockCredential): UnlockedVault = runBlocking {
        opener().open(authenticate = { c -> c }, credential = credential, authenticateBiometric = { c -> c })
    }

    private fun thrown(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        fail("expected an exception"); throw AssertionError()
    }

    private fun wrong(e: Exception, kind: AppPasswordException.Kind = AppPasswordException.Kind.WRONG_PASSWORD) =
        assertEquals(kind, (e as AppPasswordException).kind)

    /** A real vault with one item and the app password on; returns the recovery phrase. */
    private fun realVault(): String {
        val v = open(UnlockCredential.System)
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(9, 9))
        val snap = v.store.load()
        val record = JsonValue.Obj(mapOf("id" to JsonValue.Str("real-1"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Real note")))
        v.store.commit(StoreChange(snap.revision, mapOf("real-1" to Wrapper.make(Namespace.ITEM, record)), snap.meta, snap.sync))
        val key = v.localKey.copyOf()
        v.close()
        val controller = AppPasswordController(dirs, systemKey, lock, random, authenticator, cryptoBound = true, params = cheap, t = EnglishTxt())
        return runBlocking {
            val created = controller.prepare(key, pw(real))
            controller.commit(created, key, false)
            key.fill(0)
            created.phrase
        }
    }

    private fun realKey(): ByteArray = lock.unwrapPassword(pw(real))

    private fun setUpDuress(hours: Int = 2) {
        val key = realKey()
        duress.setup(key, pw(real), pw(second), hours, decoySession = false) { store ->
            val s = store.load()
            val note = JsonValue.Obj(mapOf("id" to JsonValue.Str("decoy-1"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Shopping list")))
            store.commit(StoreChange(s.revision, mapOf("decoy-1" to Wrapper.make(Namespace.ITEM, note)), s.meta, s.sync))
        }
        key.fill(0)
    }

    @Test fun setup_refuses_the_app_password_and_one_edit_variants() {
        realVault()
        val key = realKey()
        for ((candidate, code) in listOf(real to "same", "river otter lantern 43" to "close", "river otter lantern 4" to "close", "xriver otter lantern 42" to "close")) {
            val e = thrown { duress.setup(key, pw(real), pw(candidate), 2, decoySession = false) {} } as DuressException
            assertEquals(candidate, code, e.code)
        }
        assertEquals("hours", (thrown { duress.setup(key, pw(real), pw(second), 0, false) {} } as DuressException).code)
        assertEquals("hours", (thrown { duress.setup(key, pw(real), pw(second), 169, false) {} } as DuressException).code)
        assertFalse(duress.configured())
        assertFalse(File(base, DuressFiles.DIR).exists())
    }

    @Test fun the_duress_password_opens_the_second_vault_in_its_own_folder_and_holds_the_real_one() {
        realVault()
        setUpDuress(hours = 2)
        assertTrue(duress.configured())
        // A wrong try first: the duress unlock resets the count (no tell-tale back-off).
        wrong(thrown { open(UnlockCredential.Password(pw("not it at all"))) })
        assertEquals(1, settings.appPasswordFailures)
        val decoy = open(UnlockCredential.Password(pw(second)))
        assertTrue(decoy.decoy)
        assertTrue(duress.sessionOpen)
        assertTrue(duress.servicesBlocked())
        assertEquals(setOf("decoy-1"), decoy.store.load().records.keys)
        assertNull(decoy.slots.read(Slot.INSTALL_ID))
        assertEquals(0, settings.appPasswordFailures)
        assertEquals(File(base, ".lgk-d/Vault").canonicalFile, (decoy.store as LocalStore).directory.canonicalFile)
        decoy.close()
        assertEquals(clock.now + 2 * 3600, duress.heldUntil())
        // While held: the real app password is refused as wrong and counted, the shortcut and the phrase too.
        wrong(thrown { open(UnlockCredential.Password(pw(real))) })
        assertEquals(1, settings.appPasswordFailures)
        assertTrue(thrown { open(UnlockCredential.System) } is AppPasswordRequiredException)
        // The duress password still opens the second vault, and never shortens the hold.
        clock.now += 3600
        open(UnlockCredential.Password(pw(second))).close()
        assertEquals(clock.now + 2 * 3600, duress.heldUntil())
        // After the hold the real vault opens again and the hold file goes.
        clock.now += 2 * 3600 + 1
        val v = open(UnlockCredential.Password(pw(real)))
        assertFalse(v.decoy)
        assertFalse(duress.sessionOpen)
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        assertEquals(setOf("real-1"), v.store.load().records.keys)
        v.close()
        assertFalse(duress.files.hold.exists())
        assertFalse(duress.servicesBlocked())
    }

    @Test fun the_recovery_phrase_is_refused_while_held() {
        val phrase = realVault()
        setUpDuress()
        open(UnlockCredential.Password(pw(second))).close()
        wrong(thrown { open(UnlockCredential.Recovery(phrase, pw("a brand new password 99"))) }, AppPasswordException.Kind.WRONG_PHRASE)
        // The real record was not rewritten: the old password still works after the hold.
        clock.now += 3 * 3600
        open(UnlockCredential.Password(pw(real))).close()
    }

    @Test fun every_app_password_try_runs_both_derivations() {
        realVault()
        setUpDuress()
        for (p in listOf(real, second, "wrong password here")) {
            derivations.set(0)
            try { open(UnlockCredential.Password(pw(p))).close() } catch (e: Exception) {}
            assertEquals(p, 2, derivations.get())
            clock.now += 3 * 3600 // let the hold run out between tries
        }
    }

    @Test fun a_new_app_password_near_the_duress_password_is_refused() {
        realVault()
        setUpDuress()
        val key = realKey()
        for (candidate in listOf(second, "copper meadow falcon 8", "copper meadow falcon7", "copper meadow falcon 77", "Copper meadow falcon 7")) {
            assertEquals(candidate, "near_duress", (thrown { duress.checkNewPassword(key, pw(candidate), decoySession = false) } as DuressException).code)
        }
        duress.checkNewPassword(key, pw("an entirely different one 5"), decoySession = false)
        // A duress session checks nothing (no oracle against the real vault from there).
        duress.checkNewPassword(key, pw(second), decoySession = true)
        assertEquals(2, duress.realHours(key))
        key.fill(0)
    }

    @Test fun inside_a_duress_session_setup_and_remove_end_with_the_generic_refusal() {
        realVault()
        val key = realKey()
        assertEquals("generic", (thrown { duress.setup(key, pw(real), pw(second), 2, decoySession = true) {} } as DuressException).code)
        // The same checks run first.
        assertEquals("same", (thrown { duress.setup(key, pw(real), pw(real), 2, decoySession = true) {} } as DuressException).code)
        assertFalse(duress.configured())
        setUpDuress()
        assertEquals("generic", (thrown { duress.remove(decoySession = true) } as DuressException).code)
        assertTrue(duress.configured())
        assertEquals("exists", (thrown { duress.setup(key, pw(real), pw("another duress pass 3"), 2, decoySession = false) {} } as DuressException).code)
        assertTrue(duress.remove(decoySession = false))
        assertFalse(File(base, DuressFiles.DIR).exists())
        assertFalse(duress.files.real.exists())
        key.fill(0)
        // Without it the duress password is just wrong, with one derivation.
        derivations.set(0)
        wrong(thrown { open(UnlockCredential.Password(pw(second))) })
        assertEquals(1, derivations.get())
    }

    @Test fun an_unreadable_hold_file_fails_closed() {
        realVault()
        setUpDuress()
        duress.files.hold.writeText("not json")
        duress.files.hold.setLastModified(clock.now * 1000)
        assertNotNull(duress.heldUntil())
        assertTrue(duress.held())
        wrong(thrown { open(UnlockCredential.Password(pw(real))) })
    }

    @Test fun within_one_edit_counts_code_points() {
        fun near(a: String, b: String) = DuressVault.withinOneEdit(pw(a), pw(b))
        assertTrue(near("abc", "abc"))
        assertTrue(near("abc", "abd"))
        assertTrue(near("abc", "ab"))
        assertTrue(near("abc", "xabc"))
        assertTrue(near("καλη", "καλή"))
        assertTrue(near("a😀b", "ab"))
        assertFalse(near("abc", "acb"))
        assertFalse(near("abc", "a"))
        assertFalse(near("abcd", "abdc"))
    }

    @Test fun the_second_vault_gets_plausible_sample_items() {
        realVault()
        val key = realKey()
        duress.setup(key, pw(real), pw(second), 24, decoySession = false) { store ->
            DuressSamples.seed(store, app.localgatekeys.core.sync.StoreSnapshot(), EnglishTxt(), random, clock.now)
        }
        key.fill(0)
        val decoy = open(UnlockCredential.Password(pw(second)))
        val items = app.localgatekeys.android.vault.VaultItem.items(decoy.store.load())
        assertEquals(6, items.size)
        assertTrue(items.any { it.title == "Shopping list" })
        assertFalse(items.any { it.title.contains("decoy", ignoreCase = true) })
        decoy.close()
    }

    @Test fun without_a_second_vault_an_unlock_runs_one_derivation() {
        realVault()
        assertFalse(duress.configured())
        for (p in listOf(real, second)) {
            derivations.set(0)
            try { open(UnlockCredential.Password(pw(p))).close() } catch (e: Exception) {}
            assertEquals(p, 1, derivations.get())
        }
    }

    @Test fun in_a_duress_session_changing_the_app_password_changes_only_the_second_vaults() {
        realVault()
        setUpDuress(hours = 1)
        val decoy = open(UnlockCredential.Password(pw(second)))
        val key = decoy.localKey.copyOf()
        decoy.close()
        val realRecord = lock.record().encode()
        // A wrong current password is refused like any wrong password (no other wording).
        wrong(thrown { duress.changeSecondPassword(key, pw("not the password 1"), pw("fresh second pass 8"), lock) })
        // The real app password does not count as the current one here either.
        wrong(thrown { duress.changeSecondPassword(key, pw(real), pw("fresh second pass 8"), lock) })
        duress.changeSecondPassword(key, pw(second), pw("fresh second pass 8"), lock)
        key.fill(0)
        assertArrayEquals(realRecord, lock.record().encode())
        wrong(thrown { open(UnlockCredential.Password(pw(second))) })
        val again = open(UnlockCredential.Password(pw("fresh second pass 8")))
        assertTrue(again.decoy)
        assertEquals(setOf("decoy-1"), again.store.load().records.keys)
        again.close()
        // The real vault keeps its own password once the hold is over.
        clock.now += 2 * 3600
        val v = open(UnlockCredential.Password(pw(real)))
        assertFalse(v.decoy)
        v.close()
    }

    @Test fun erase_in_a_duress_session_erases_only_the_second_vaults_data() {
        realVault()
        setUpDuress(hours = 2)
        val decoy = open(UnlockCredential.Password(pw(second)))
        decoy.slots.write(Slot.INSTALL_ID, byteArrayOf(5))
        decoy.close()
        File(duress.files.attachments, "doc.bin").apply { parentFile!!.mkdirs(); writeBytes(byteArrayOf(1)) }
        duress.files.draft.writeBytes(byteArrayOf(2))
        val until = duress.heldUntil()
        assertTrue(duress.eraseSecondVault())
        assertFalse(duress.files.vault.exists())
        assertFalse(duress.files.secrets.exists())
        assertFalse(duress.files.draft.exists())
        // The real vault and its hold are untouched; the duress password opens an empty vault.
        assertTrue(dirs.vault.isDirectory)
        assertTrue(duress.files.real.exists())
        assertEquals(until, duress.heldUntil())
        val empty = open(UnlockCredential.Password(pw(second)))
        assertTrue(empty.decoy)
        assertTrue(empty.store.load().records.isEmpty())
        assertNull(empty.slots.read(Slot.INSTALL_ID))
        empty.close()
        clock.now += 3 * 3600
        val v = open(UnlockCredential.Password(pw(real)))
        assertEquals(setOf("real-1"), v.store.load().records.keys)
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        v.close()
    }

    @Test fun the_second_vault_carries_the_licence_states() {
        realVault()
        val key = realKey()
        val licence = Wrapper.make(Namespace.LICENSE, JsonValue.Obj(mapOf("bundle" to JsonValue.Str("signed"))))
        val id = app.localgatekeys.core.records.License.ID_PREFIX + "0123456789abcdef0123456789abcdef"
        val realSnap = app.localgatekeys.core.sync.StoreSnapshot(mapOf(id to licence))
        duress.setup(key, pw(real), pw(second), 24, decoySession = false) { store ->
            DuressSamples.seed(store, realSnap, EnglishTxt(), random, clock.now)
        }
        key.fill(0)
        val decoy = open(UnlockCredential.Password(pw(second)))
        assertEquals(licence, decoy.store.load().records[id])
        decoy.close()
    }

    @Test fun a_duress_sessions_reminders_plan_into_its_own_book() {
        val alarms = DuressPlaces.reminderAlarms(duress.files)
        alarms.replaceAll(listOf(app.localgatekeys.android.reminders.AlarmEntry("r1", null, null)))
        assertEquals(listOf("r1"), alarms.entries().map { it.id })
        assertTrue(File(duress.files.dir, "reminder-alarms.json").exists())
        assertFalse(File(base, "reminder-alarms.json").exists())
    }

    @Test fun the_real_vaults_reminders_post_nothing_while_held_or_in_a_duress_session() {
        val set = ArrayList<String>()
        val setter = object : app.localgatekeys.android.reminders.AlarmSetter {
            override fun set(id: String, atMillis: Long) { set += id }
            override fun cancel(id: String) {}
        }
        val alarms = app.localgatekeys.android.reminders.ReminderAlarms(File(base, "reminder-alarms.json"), setter)
        alarms.replaceAll(listOf(app.localgatekeys.android.reminders.AlarmEntry("r1", null, "Bank")))
        val posted = ArrayList<String>()
        fun fire() = app.localgatekeys.android.reminders.ReminderDelivery.fire(
            alarms, "r1", withheld = { duress.servicesBlocked() }, show = { posted += it.id; true }, today = { "2027-01-15" },
        )
        // A duress session is open: nothing is posted and the alarm entry stays.
        duress.sessionOpen = true
        assertFalse(fire())
        duress.sessionOpen = false
        // The real vault is held (also in a fresh process: the hold is on disk).
        duress.trip(ByteArray(32))
        assertTrue(duress.held())
        assertFalse(fire())
        assertTrue(posted.isEmpty())
        assertNotNull(alarms.entry("r1"))
        // After the hold the reminder is posted as usual.
        clock.now += (DuressVault.MAX_HOURS + 1) * 3600L
        assertTrue(fire())
        assertEquals(listOf("r1"), posted)
        assertNull(alarms.entry("r1"))
    }

    @Test fun settings_password_change_takes_the_duress_path_only_in_a_duress_session() = runBlocking {
        realVault()
        setUpDuress(hours = 1)
        val decoy = open(UnlockCredential.Password(pw(second)))
        val key = decoy.localKey.copyOf()
        decoy.close()
        var inSession = true
        var realCalls = 0
        val routing = DuressRouting({ inSession }, duress, lock, kotlinx.coroutines.Dispatchers.Unconfined)
        routing.changePassword(key, second, "fresh second pass 8") { realCalls++ }
        assertEquals(0, realCalls)
        assertNotNull(duress.tryOpen(pw("fresh second pass 8"))?.also { it.fill(0) })
        assertNull(duress.tryOpen(pw(second)))
        // A real session runs the real change and leaves the second vault alone.
        inSession = false
        routing.changePassword(realKey(), real, "another real pass 3") { realCalls++ }
        assertEquals(1, realCalls)
        assertNotNull(duress.tryOpen(pw("fresh second pass 8"))?.also { it.fill(0) })
        key.fill(0)
    }

    @Test fun settings_erase_takes_the_duress_path_only_in_a_duress_session() = runBlocking {
        realVault()
        setUpDuress(hours = 1)
        open(UnlockCredential.Password(pw(second))).close()
        var inSession = true
        val steps = ArrayList<String>()
        val routing = DuressRouting({ inSession }, duress, lock, kotlinx.coroutines.Dispatchers.Unconfined)
        assertTrue(routing.erase(lockAndWait = { steps += "lock" }) { steps += "real"; true })
        assertEquals(listOf("lock"), steps)
        assertFalse(duress.files.vault.exists())
        assertTrue(dirs.vault.isDirectory)
        assertTrue(duress.configured())
        // A real session runs the full erase (here a stand-in) and never the second vault's.
        inSession = false
        open(UnlockCredential.Password(pw(second))).close() // the second vault has data again
        steps.clear()
        assertTrue(routing.erase(lockAndWait = { steps += "lock" }) { steps += "real"; true })
        assertEquals(listOf("real"), steps)
        assertTrue(duress.files.vault.exists())
    }

    @Test fun the_second_vault_password_change_is_throttled_like_the_real_one() {
        realVault()
        setUpDuress(hours = 1)
        val decoy = open(UnlockCredential.Password(pw(second)))
        val key = decoy.localKey.copyOf()
        decoy.close()
        assertEquals(0, settings.appPasswordFailures)
        // Wrong current passwords count like the real change's (one shared count), up to the delay.
        for (i in 1..app.localgatekeys.core.crypto.AppPasswordDelay.FREE_TRIES + 1) {
            wrong(thrown { duress.changeSecondPassword(key, pw("wrong one $i"), pw("fresh second pass 8"), lock) })
            assertEquals(i, settings.appPasswordFailures)
        }
        assertTrue(lock.waitSeconds() > 0)
        derivations.set(0)
        val e = thrown { duress.changeSecondPassword(key, pw(second), pw("fresh second pass 8"), lock) }
        assertTrue(e is app.localgatekeys.android.vault.AppPasswordWaitException)
        assertEquals("refused before any derivation", 0, derivations.get())
        // After the delay the right password works and resets the count, as the real change does.
        clock.now += 3600
        duress.changeSecondPassword(key, pw(second), pw("fresh second pass 8"), lock)
        assertEquals(0, settings.appPasswordFailures)
        key.fill(0)
    }

    @Test fun held_real_password_and_phrase_grow_the_delay_like_wrong_ones() {
        val phrase = realVault()
        setUpDuress(hours = DuressVault.MAX_HOURS)
        open(UnlockCredential.Password(pw(second))).close()
        fun waits(credential: () -> UnlockCredential): List<Long> {
            settings.appPasswordFailures = 0
            val out = ArrayList<Long>()
            repeat(7) {
                thrown { open(credential()) }
                out += lock.waitSeconds()
                clock.now += lock.waitSeconds() + 1
            }
            return out
        }
        val wrongOnes = waits { UnlockCredential.Password(pw("not it at all")) }
        assertTrue(wrongOnes.last() > 0)
        // While held the real password is refused as wrong and must not stand out: the same growing delay.
        assertEquals(wrongOnes, waits { UnlockCredential.Password(pw(real)) })
        // The recovery phrase likewise (against a wrong phrase).
        val wrongPhrase = waits { UnlockCredential.Recovery("abandon ".repeat(23) + "art", pw("a brand new password 99")) }
        assertEquals(wrongPhrase, waits { UnlockCredential.Recovery(phrase, pw("a brand new password 99")) })
        assertTrue(duress.held())
    }
}
