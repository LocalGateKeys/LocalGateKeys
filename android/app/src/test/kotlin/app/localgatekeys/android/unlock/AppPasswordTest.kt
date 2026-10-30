package app.localgatekeys.android.unlock

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.vault.AppPasswordAttempts
import app.localgatekeys.android.vault.AppPasswordFiles
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.AppPasswordRequiredException
import app.localgatekeys.android.vault.AppPasswordWaitException
import app.localgatekeys.android.vault.BiometricChangedException
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.primitives.SystemRandomSource
import java.io.File
import javax.crypto.Cipher
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/** Task 7 on Android: the app password around the unchanged local key (opener, Settings controller, erase). */
class AppPasswordTest {
    private lateinit var base: File
    private lateinit var dirs: VaultDirs
    private lateinit var systemKey: RecordingVaultKey
    private lateinit var bioKey: FakeVaultKey
    private lateinit var settings: AppSettings
    private lateinit var clock: TestClock
    private val boot = object : BootClock {
        override var elapsed = 1_000L
        override var boot = 7L
    }
    private lateinit var lock: AppPasswordLock
    private lateinit var controller: AppPasswordController
    private val random = SystemRandomSource()
    private val cheap = AppPasswordParams(memoryKiB = 8192, iterations = 1, parallelism = 1)
    private val systemPrompts = mutableListOf<String>()
    private val bioPrompts = mutableListOf<String>()
    private var bioFails: Exception? = null

    private val authenticator = object : Authenticator {
        override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? { systemPrompts += reason; return cipher }
        override suspend fun authenticateBiometric(reason: String, cipher: Cipher): Cipher? {
            bioPrompts += reason
            bioFails?.let { throw it }
            return cipher
        }
        override fun cancel() {}
    }

    @Before fun setUp() {
        base = tempDir("app-password")
        dirs = VaultDirs.under(base)
        systemKey = RecordingVaultKey()
        bioKey = FakeVaultKey()
        settings = AppSettings(MemoryStore())
        clock = TestClock(1_000_000)
        lock = AppPasswordLock(AppPasswordFiles.under(base), bioKey, random, AppPasswordAttempts.of(settings), clock, bootClock = boot)
        controller = AppPasswordController(dirs, systemKey, lock, random, authenticator, cryptoBound = true, params = cheap, t = EnglishTxt())
    }

    private fun opener() = VaultOpener(dirs, systemKey, random, null, cryptoBound = true, appPassword = lock)

    private fun open(credential: UnlockCredential = UnlockCredential.System): UnlockedVault = runBlocking {
        opener().open(
            authenticate = { c -> systemPrompts += "system"; c },
            credential = credential,
            authenticateBiometric = { c -> authenticator.authenticateBiometric("bio", c) },
        )
    }

    private fun pw(s: String) = AppPasswordRecord.passwordBytes(s)

    private fun thrown(block: () -> Unit): Exception {
        try { block() } catch (e: Exception) { return e }
        fail("expected an exception"); throw AssertionError()
    }

    /** A vault opened the old way, with one secret, then the app password turned on. Returns the phrase. */
    private fun vaultWithPassword(password: String = "river otter lantern 42", biometric: Boolean = false): String {
        val v = open()
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(9, 9))
        val key = v.localKey.copyOf()
        v.close()
        return runBlocking {
            val created = controller.prepare(key, pw(password))
            controller.commit(created, key, biometric)
            key.fill(0)
            created.phrase
        }
    }

    @Test fun migration_without_a_password_file_today_s_unlock_is_unchanged() {
        val v = open()
        v.close()
        systemPrompts.clear()
        val again = open()
        assertEquals(listOf("system"), systemPrompts)
        assertFalse(lock.isOn())
        again.close()
        assertTrue(thrown { open(UnlockCredential.Password(pw("x"))) } is IllegalStateException)
    }

    @Test fun turning_on_removes_the_passcode_capable_key_and_the_password_opens_the_same_vault() {
        vaultWithPassword()
        assertTrue(lock.isOn())
        assertFalse("passcode-capable key deleted", systemKey.exists())
        assertFalse("vault-key.bin deleted", dirs.wrappedKey.exists())
        systemPrompts.clear()
        // The system prompt (screen lock) cannot open it any more.
        assertTrue(thrown { open() } is AppPasswordRequiredException)
        assertTrue(systemPrompts.isEmpty())
        val v = open(UnlockCredential.Password(pw("river otter lantern 42")))
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        v.close()
    }

    @Test fun the_password_bytes_are_zeroed_after_use() {
        vaultWithPassword()
        val bytes = pw("river otter lantern 42")
        open(UnlockCredential.Password(bytes)).close()
        assertTrue(bytes.all { it == 0.toByte() })
    }

    @Test fun wrong_password_fails_and_the_delay_starts_at_the_fifth() {
        vaultWithPassword()
        repeat(4) {
            val e = thrown { open(UnlockCredential.Password(pw("wrong"))) }
            assertEquals(AppPasswordException.Kind.WRONG_PASSWORD, (e as AppPasswordException).kind)
        }
        assertEquals(0, lock.waitSeconds())
        thrown { open(UnlockCredential.Password(pw("wrong"))) }
        assertEquals(30, lock.waitSeconds())
        // Even the right password waits.
        assertTrue(thrown { open(UnlockCredential.Password(pw("river otter lantern 42"))) } is AppPasswordWaitException)
        clock.now += 30; boot.elapsed += 30
        open(UnlockCredential.Password(pw("river otter lantern 42"))).close()
        assertEquals(0, settings.appPasswordFailures)
    }

    @Test fun recovery_phrase_unlocks_and_sets_the_new_password() {
        val phrase = vaultWithPassword()
        val v = open(UnlockCredential.Recovery(phrase, pw("a fresh new password 7")))
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        v.close()
        open(UnlockCredential.Password(pw("a fresh new password 7"))).close()
        assertTrue(thrown { open(UnlockCredential.Password(pw("river otter lantern 42"))) } is AppPasswordException)
        // The phrase still works afterwards.
        open(UnlockCredential.Recovery(phrase, pw("third password here 9"))).close()
    }

    @Test fun a_wrong_phrase_counts_as_a_wrong_try() {
        vaultWithPassword()
        val other = AppPasswordRecord.create(random.bytes(32), pw("p"), random, cheap).phrase
        val e = thrown { open(UnlockCredential.Recovery(other, pw("new one"))) }
        assertEquals(AppPasswordException.Kind.WRONG_PHRASE, (e as AppPasswordException).kind)
        assertEquals(1, settings.appPasswordFailures)
    }

    @Test fun biometric_shortcut_opens_with_a_biometric_only_prompt() {
        vaultWithPassword(biometric = true)
        assertTrue(lock.biometricOn())
        systemPrompts.clear(); bioPrompts.clear()
        val v = open()
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        v.close()
        assertTrue("never the screen-lock prompt", systemPrompts.isEmpty())
        assertEquals(1, bioPrompts.size)
    }

    @Test fun changed_biometrics_remove_the_shortcut_and_ask_for_the_password() {
        vaultWithPassword(biometric = true)
        bioKey.invalidate()
        assertTrue(thrown { open() } is BiometricChangedException)
        assertFalse(lock.biometricOn())
        assertTrue(thrown { open() } is AppPasswordRequiredException)
        open(UnlockCredential.Password(pw("river otter lantern 42"))).close()
    }

    @Test fun a_cancelled_biometric_prompt_at_turn_on_leaves_password_only() {
        bioFails = AuthenticationException(13)
        vaultWithPassword(biometric = true)
        assertTrue(lock.isOn())
        assertFalse(lock.biometricOn())
        assertFalse(systemKey.exists())
    }

    @Test fun change_needs_the_current_password() {
        vaultWithPassword()
        val key = open(UnlockCredential.Password(pw("river otter lantern 42"))).let { v -> v.localKey.copyOf().also { v.close() } }
        runBlocking {
            assertTrue(thrown { runBlocking { controller.change(key, pw("not it"), pw("new password 123")) } } is AppPasswordException)
            controller.change(key, pw("river otter lantern 42"), pw("new password 123"))
        }
        open(UnlockCredential.Password(pw("new password 123"))).close()
        assertTrue(thrown { open(UnlockCredential.Password(pw("river otter lantern 42"))) } is AppPasswordException)
    }

    @Test fun turning_off_needs_the_password_and_restores_today_s_unlock() {
        vaultWithPassword(biometric = true)
        val key = open(UnlockCredential.Password(pw("river otter lantern 42"))).let { v -> v.localKey.copyOf().also { v.close() } }
        assertTrue(thrown { runBlocking { controller.turnOff(key, pw("wrong"), "off") } } is AppPasswordException)
        assertTrue(lock.isOn())
        runBlocking { controller.turnOff(key, pw("river otter lantern 42"), "off") }
        assertFalse(lock.isOn())
        assertFalse(lock.biometricOn())
        assertTrue(systemKey.exists())
        assertTrue(dirs.wrappedKey.exists())
        systemPrompts.clear()
        val v = open()
        assertEquals(listOf("system"), systemPrompts)
        assertArrayEquals(byteArrayOf(9, 9), v.slots.read(Slot.INSTALL_ID))
        v.close()
    }

    @Test fun an_interrupted_turn_on_is_finished_by_the_next_password_unlock() {
        val v = open()
        val key = v.localKey.copyOf()
        v.close()
        // Crash after the password file was written, before the passcode-capable key was deleted.
        runBlocking { lock.write(controller.prepare(key, pw("river otter lantern 42")).record) }
        assertTrue(systemKey.exists())
        assertTrue(thrown { open() } is AppPasswordRequiredException)
        open(UnlockCredential.Password(pw("river otter lantern 42"))).close()
        assertFalse(systemKey.exists())
        assertFalse(dirs.wrappedKey.exists())
    }

    @Test fun moving_the_clock_forward_does_not_skip_the_delay() {
        vaultWithPassword()
        repeat(5) { thrown { open(UnlockCredential.Password(pw("wrong password 123"))) } }
        assertEquals(30, lock.waitSeconds())
        clock.now += 86_400   // the date set a day forward, same boot
        assertEquals(30, lock.waitSeconds())
        assertTrue(thrown { open(UnlockCredential.Password(pw("river otter lantern 42"))) } is AppPasswordWaitException)
        boot.elapsed += 30
        assertEquals(0, lock.waitSeconds())
        open(UnlockCredential.Password(pw("river otter lantern 42"))).close()
    }

    @Test fun after_a_restart_the_wall_clock_decides_the_delay() {
        vaultWithPassword()
        repeat(5) { thrown { open(UnlockCredential.Password(pw("wrong password 123"))) } }
        boot.boot = 8; boot.elapsed = 5
        assertEquals(30, lock.waitSeconds())
        clock.now += 10
        assertEquals(20, lock.waitSeconds())
    }

    @Test fun app_start_removes_the_passcode_key_left_by_an_interrupted_turn_on() {
        val v = open()
        val key = v.localKey.copyOf()
        v.close()
        // Crash after the password file was written, before the passcode-capable key was deleted.
        runBlocking { lock.write(controller.prepare(key, pw("river otter lantern 42")).record) }
        assertTrue(systemKey.exists())
        assertTrue(dirs.wrappedKey.exists())
        controller.finishTurnOn()
        assertFalse(systemKey.exists())
        assertFalse(dirs.wrappedKey.exists())
        assertEquals(listOf("system"), systemPrompts)
        open(UnlockCredential.Password(pw("river otter lantern 42"))).close()
    }

    @Test fun app_start_keeps_the_passcode_key_while_the_password_is_off() {
        open().close()
        controller.finishTurnOn()
        assertTrue(systemKey.exists())
        assertTrue(dirs.wrappedKey.exists())
    }

    @Test fun erase_removes_the_password_file_and_the_shortcut() {
        vaultWithPassword(biometric = true)
        runBlocking { VaultEraser(dirs, systemKey, settings, appPassword = lock).erase() }
        assertFalse(lock.isOn())
        assertFalse(lock.biometricOn())
        assertFalse(bioKey.exists())
        // The next unlock is a first run with today's prompt.
        open().close()
        assertTrue(systemKey.exists())
    }
}

/** The setup screen's rules: three distinct word positions, the typed words checked. */
class AppPasswordTextTest {
    @Test fun confirm_positions_and_words() {
        repeat(50) {
            val p = app.localgatekeys.android.settings.AppPasswordText.confirmPositions(SystemRandomSource())
            assertEquals(3, p.toSet().size)
            assertTrue(p.all { it in 0..23 })
            assertEquals(p.sorted(), p)
        }
        val phrase = (0 until 24).joinToString(" ") { "w$it" }
        assertTrue(app.localgatekeys.android.settings.AppPasswordText.confirms(phrase, listOf(0, 5, 23), listOf("w0", " W5 ", "w23")))
        assertFalse(app.localgatekeys.android.settings.AppPasswordText.confirms(phrase, listOf(0, 5, 23), listOf("w0", "w6", "w23")))
    }
}

/** The lock model in password mode: no screen-lock prompt, the password field instead. */
class AppPasswordLockModelTest {
    private val clock = TestClock(1000)
    private val settings = AppSettings(MemoryStore())

    private class CredentialUnlocker(val inner: FakeUnlocker = FakeUnlocker()) : Unlocker by inner {
        val credentials = mutableListOf<String>()
        var failWith: Exception? = null
        override suspend fun unlock(reason: String, credential: UnlockCredential): UnlockedVault {
            credentials += credential.toString()
            failWith?.let { throw it }
            return inner.unlock(reason)
        }
    }

    private fun model(u: Unlocker, bio: Boolean) = AppLockModel(
        u, clock, ManualScheduler(clock), settings, null, FakeEraser(),
        passwordOn = { true }, biometricShortcut = { bio },
        t = EnglishTxt(),
    )

    @Test fun password_on_without_shortcut_never_prompts() = runBlocking {
        val u = CredentialUnlocker()
        val m = model(u, bio = false)
        m.sceneBecameActive()
        assertEquals(0, u.inner.unlockCalls)
        assertTrue(m.needsPassword.value)
        assertEquals(AppLockModel.State.LOCKED, m.state.value)
        m.unlockWithPassword("secret words")
        assertEquals(listOf("Password"), u.credentials)
        assertEquals(AppLockModel.State.UNLOCKED, m.state.value)
        assertFalse(m.needsPassword.value)
    }

    @Test fun cancelled_shortcut_shows_the_password_field() = runBlocking {
        val u = CredentialUnlocker()
        u.inner.succeed = false
        u.inner.error = AuthenticationException(androidx.biometric.BiometricPrompt.ERROR_NEGATIVE_BUTTON)
        val m = model(u, bio = true)
        m.unlock()
        assertEquals(1, u.inner.unlockCalls)
        assertTrue(m.needsPassword.value)
        assertEquals(null, m.errorMessage.value)
    }

    @Test fun wrong_password_and_delay_messages() = runBlocking {
        val u = CredentialUnlocker()
        val m = model(u, bio = false)
        u.failWith = AppPasswordException(AppPasswordException.Kind.WRONG_PASSWORD)
        m.unlockWithPassword("nope")
        assertEquals(EnglishTxt().s(AppLockModel.WRONG_PASSWORD_MESSAGE), m.errorMessage.value)
        u.failWith = AppPasswordWaitException(30)
        m.unlockWithPassword("nope")
        assertEquals("Too many wrong tries. Try again in 30 seconds.", m.errorMessage.value)
        assertFalse(m.offersStartFresh.value)
        u.failWith = AppPasswordException(AppPasswordException.Kind.MALFORMED)
        m.unlockWithPassword("any")
        assertEquals(EnglishTxt().s(AppLockModel.MALFORMED_MESSAGE), m.errorMessage.value)
        assertFalse(EnglishTxt().s(AppLockModel.MALFORMED_MESSAGE).contains("Use your recovery phrase"))
        assertTrue(EnglishTxt().s(AppLockModel.MALFORMED_MESSAGE).contains("Start fresh"))
        assertTrue(m.offersStartFresh.value)
        u.failWith = null
        m.recover("phrase", "new password")
        assertEquals(listOf("Password", "Password", "Password", "Recovery"), u.credentials)
        assertEquals(AppLockModel.State.UNLOCKED, m.state.value)
    }
}
