package app.localgatekeys.android.unlock

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.settings.MemoryStore
import app.localgatekeys.android.unlock.AppLockModel.State
import app.localgatekeys.android.unlock.AppPasswordController.FactorChange
import app.localgatekeys.android.vault.AppPasswordAttempts
import app.localgatekeys.android.vault.AppPasswordFiles
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.AppPasswordRequiredException
import app.localgatekeys.android.vault.BootClock
import app.localgatekeys.android.vault.FakeVaultKey
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.CompositeKey
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.core.crypto.KeyFile
import app.localgatekeys.core.primitives.SystemRandomSource
import java.io.File
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * KeePass unlocking Task 9 on Android: the app password with a key file and a YubiKey, through the real opener, lock
 * file and lock model, over a fake [FactorSource] (a key "file" in memory and a YubiKey modelled in variable-input mode).
 */
class FactorUnlockModelTest {
    private lateinit var base: File
    private lateinit var settings: AppSettings
    private lateinit var lock: AppPasswordLock
    private lateinit var controller: AppPasswordController
    private lateinit var source: FakeFactorSource
    private lateinit var clock: TestClock
    private val random = SystemRandomSource()
    private val cheap = AppPasswordParams(memoryKiB = 8192, iterations = 1, parallelism = 1)
    private val password = "river otter lantern 42"
    private val dirs get() = VaultDirs.under(base)
    private val systemKey = RecordingVaultKey()
    private val bioKey = FakeVaultKey()
    private val txt = EnglishTxt()
    private var dropped = 0

    private val authenticator = object : Authenticator {
        override suspend fun authenticate(reason: String, cipher: Cipher?): Cipher? = cipher
        override fun cancel() {}
    }

    /** Key "files" by URI, and a YubiKey slot secret answering like a variable-input slot (trailing pad dropped). */
    class FakeFactorSource : FactorSource {
        val files = HashMap<String, ByteArray>()
        var remembered: KeyFileRef? = null
        var slotSecret: ByteArray? = "vector-hmac-secret".toByteArray()
        /** Thrown, in order, before the key answers. */
        val failures = ArrayDeque<YubiKeyException>()
        val challenges = mutableListOf<ByteArray>()
        var cancelled = 0
        /** Runs as each YubiKey exchange starts (tests look at the screen's prompt then). */
        var onAsk: (() -> Unit)? = null

        /** False: "Don't remember". */
        var remembering = true
        /** What the model asked to keep (grant persisted) and to give back. */
        val rememberCalls = mutableListOf<KeyFileRef>()
        val releases = mutableListOf<KeyFileRef>()

        override fun rememberedKeyFile() = remembered
        override fun remembers() = remembering
        override suspend fun readKeyFile(ref: KeyFileRef): ByteArray = files[ref.uri]?.copyOf() ?: throw KeyFileUnreadableException(ref.name)
        override fun rememberKeyFile(ref: KeyFileRef) {
            rememberCalls += ref
            if (remembering) remembered = ref
        }
        override fun releaseKeyFile(ref: KeyFileRef) { releases += ref }
        override suspend fun yubiKey(slot: Int, challenge: ByteArray): ByteArray {
            challenges += challenge.copyOf()
            onAsk?.invoke()
            failures.removeFirstOrNull()?.let { throw it }
            val secret = slotSecret ?: throw YubiKeyException(YubiKeyException.Code.SLOT_NOT_CONFIGURED, slot)
            return variableModeHmac(secret, challenge)
        }
        override fun cancelYubiKey() { cancelled++ }

        companion object {
            fun variableModeHmac(secret: ByteArray, padded: ByteArray): ByteArray {
                var end = padded.size
                val last = padded[end - 1]
                while (end > 0 && padded[end - 1] == last) end--
                val mac = Mac.getInstance("HmacSHA1")
                mac.init(SecretKeySpec(secret, "HmacSHA1"))
                return mac.doFinal(padded.copyOf(end))
            }
        }
    }

    private val keyFileBytes = KeyFile.keepassXmlV2(ByteArray(32) { (it * 7 + 1).toByte() })
    private val keyFileRef = KeyFileRef("content://test/keyfile", "vault.keyx")

    @Before fun setUp() {
        base = tempDir("factor-unlock")
        settings = AppSettings(MemoryStore())
        clock = TestClock(1_000_000)
        lock = AppPasswordLock(AppPasswordFiles.under(base), bioKey, random, AppPasswordAttempts.of(settings), clock, bootClock = BootClock.NONE)
        controller = AppPasswordController(dirs, systemKey, lock, random, authenticator, cryptoBound = true, params = cheap, t = txt)
        source = FakeFactorSource()
        source.files[keyFileRef.uri] = keyFileBytes
    }

    private fun opener() = VaultOpener(dirs, systemKey, random, null, cryptoBound = true, appPassword = lock, alwaysAskFactors = { settings.factorsAlwaysAsk })

    private fun model() = AppLockModel(
        VaultUnlocker(opener(), authenticator), clock, ManualScheduler(clock), settings, null, FakeEraser(),
        passwordOn = { lock.isOn() }, biometricShortcut = { lock.biometricOn() }, t = txt,
        factorSource = source, factors = { lock.factors() }, onFactorsDropped = { dropped++ },
    )

    private fun input(keyFile: KeyFileRef? = keyFileRef) = FactorInput(
        keyFile = { keyFile?.let { source.readKeyFile(it) } },
        yubiKey = { slot, challenge -> source.yubiKey(slot, challenge) },
    )

    /** A vault opened the old way (one secret), the app password turned on, then the key file and/or YubiKey added. */
    private fun vaultWithFactors(keyFile: Boolean = true, yubiKey: Boolean = true, biometric: Boolean = false): String = runBlocking {
        val v = opener().open(authenticate = { it })
        v.slots.write(Slot.INSTALL_ID, byteArrayOf(9, 9))
        val key = v.localKey.copyOf()
        v.close()
        val created = controller.prepare(key, AppPasswordRecord.passwordBytes(password))
        controller.commit(created, key, biometric)
        if (keyFile) controller.changeFactors(key, pw(), input(null), FactorChange.AddKeyFile(keyFileBytes.copyOf()))
        if (yubiKey) controller.changeFactors(key, pw(), input(), FactorChange.AddYubiKey(2))
        key.fill(0)
        source.challenges.clear()
        created.phrase
    }

    private fun pw(s: String = password) = AppPasswordRecord.passwordBytes(s)

    private fun lockedModel(): AppLockModel = runBlocking { model().also { it.unlock() } }

    @Test fun missingFactorRequired() = runBlocking {
        vaultWithFactors()
        assertEquals(listOf(FactorKind.KEYFILE, FactorKind.YUBIKEY_HMAC), lock.factors().map { it.kind })
        val m = lockedModel()
        assertTrue(m.needsPassword.value)
        assertEquals(2, m.factorSpecs.value.size)
        assertNull("nothing remembered yet", m.keyFile.value)
        m.unlockWithPassword(password)
        assertEquals(State.LOCKED, m.state.value)
        assertEquals("This vault also needs its key file.", m.errorMessage.value)
        assertTrue("the YubiKey is not asked before the key file", source.challenges.isEmpty())
        assertEquals("never a counted try", 0, settings.appPasswordFailures)
        // Without any factors supplied the opener refuses before Argon2id, naming both.
        val e = runCatching { opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw())) }.exceptionOrNull()
        assertEquals("This vault also needs its key file and YubiKey.", AppLockModel.message(e!!, txt))
        assertEquals(0, settings.appPasswordFailures)
    }

    @Test fun mismatchMessage() = runBlocking {
        vaultWithFactors()
        val m = lockedModel()
        // Another key file, or the same file edited on disk.
        source.files["content://test/other"] = KeyFile.keepassXmlV2(ByteArray(32) { 3 })
        m.chooseKeyFile(KeyFileRef("content://test/other", "other.keyx"), remember = true)
        m.unlockWithPassword(password)
        assertEquals("This isn't the key file used for this vault.", m.errorMessage.value)
        assertTrue(source.challenges.isEmpty())
        source.files[keyFileRef.uri] = KeyFile.keepassXmlV2(ByteArray(32) { 5 })
        m.chooseKeyFile(keyFileRef, remember = true)
        m.unlockWithPassword(password)
        assertEquals("This isn't the key file used for this vault.", m.errorMessage.value)
        source.files[keyFileRef.uri] = KeyFile.keepassXmlV2(ByteArray(32)).copyOf(40) // cut short: malformed XML
        m.unlockWithPassword(password)
        assertEquals("This file can't be used as a key file.", m.errorMessage.value)
        source.files[keyFileRef.uri] = keyFileBytes
        // The right file, another YubiKey.
        source.slotSecret = "another secret".toByteArray()
        m.unlockWithPassword(password)
        assertEquals("This isn't the YubiKey used for this vault.", m.errorMessage.value)
        assertEquals("the 64-byte padded challenge, as stored", 64, source.challenges.single().size)
        assertArrayEquals(lock.factors()[1].paddedChallenge, source.challenges.single())
        assertEquals(0, settings.appPasswordFailures)
        assertNull("a failed try remembers nothing", source.remembered)
        // Both factors right, the password wrong: that one counts.
        source.slotSecret = "vector-hmac-secret".toByteArray()
        m.unlockWithPassword("not the password")
        assertEquals(txt.s(AppLockModel.WRONG_PASSWORD_MESSAGE), m.errorMessage.value)
        assertEquals(1, settings.appPasswordFailures)
        m.unlockWithPassword(password)
        assertEquals(State.UNLOCKED, m.state.value)
        assertArrayEquals(byteArrayOf(9, 9), m.vault.value!!.slots.read(Slot.INSTALL_ID))
        assertEquals("the picked key file is remembered after it worked", keyFileRef, source.remembered)
        assertEquals(0, settings.appPasswordFailures)
    }

    @Test fun recoveryPhraseBypassesFactors() = runBlocking {
        val phrase = vaultWithFactors()
        val before = lock.files.record.readBytes()
        val m = lockedModel()
        m.recover(phrase, "a fresh new password 7")
        assertEquals(State.UNLOCKED, m.state.value)
        assertTrue("no YubiKey, no key file", source.challenges.isEmpty())
        assertEquals("Key file / YubiKey removed; add them again.", m.notice.value)
        assertEquals(1, dropped)
        // The new password has no factors: v1 again, with the recovery wrapper unchanged.
        val after = lock.files.record.readBytes()
        assertEquals(AppPasswordRecord.SIZE, after.size)
        assertArrayEquals(before.copyOfRange(before.size - 76, before.size), after.copyOfRange(after.size - 76, after.size))
        assertTrue(lock.factors().isEmpty())
        m.lock()
        m.unlock()
        assertTrue(m.factorSpecs.value.isEmpty())
        m.unlockWithPassword("a fresh new password 7")
        assertEquals(State.UNLOCKED, m.state.value)
    }

    @Test fun autofillDefersWhenFactorsSet() = runBlocking {
        vaultWithFactors(keyFile = false, yubiKey = false)
        val plain = lockedModel()
        assertFalse("the app password alone: the sheet unlocks itself", plain.sheetDefersToApp())
        val key = opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw())).let { v -> v.localKey.copyOf().also { v.close() } }
        controller.changeFactors(key, pw(), null, FactorChange.AddKeyFile(keyFileBytes.copyOf()))
        key.fill(0)
        val m = lockedModel()
        assertTrue(m.sheetDefersToApp())
        source.remembered = keyFileRef
        m.unlock()
        assertEquals(keyFileRef, m.keyFile.value)
        m.unlockWithPassword(password)
        assertEquals(State.UNLOCKED, m.state.value)
        assertFalse("already open: the sheet fills", m.sheetDefersToApp())
    }

    @Test fun deviceRemovedMidwayRetries() = runBlocking {
        vaultWithFactors(keyFile = false)
        val m = lockedModel()
        val prompts = mutableListOf<AppLockModel.YubiKeyPrompt?>()
        // The key left the reader once (NFC tag lost): asked again in the same try, nothing counted.
        source.failures += YubiKeyException(YubiKeyException.Code.REMOVED, 2)
        source.onAsk = { prompts += m.yubiKeyPrompt.value }
        m.unlockWithPassword(password)
        assertEquals(State.UNLOCKED, m.state.value)
        assertEquals(2, source.challenges.size)
        assertEquals(listOf(AppLockModel.YubiKeyPrompt(2, again = false), AppLockModel.YubiKeyPrompt(2, again = true)), prompts)
        assertNull(m.yubiKeyPrompt.value)
        assertEquals(0, settings.appPasswordFailures)
        m.lock()
        // Gone three times: "Touch your YubiKey again", still not a counted try.
        source.challenges.clear()
        repeat(AppLockModel.YUBIKEY_TRIES) { source.failures += YubiKeyException(YubiKeyException.Code.REMOVED, 2) }
        m.unlock()
        m.unlockWithPassword(password)
        assertEquals(State.LOCKED, m.state.value)
        assertEquals("Touch your YubiKey again.", m.errorMessage.value)
        assertEquals(AppLockModel.YUBIKEY_TRIES, source.challenges.size)
        assertEquals(0, settings.appPasswordFailures)
        // Cancelled: no message at all.
        source.failures += YubiKeyException(YubiKeyException.Code.CANCELLED, 2)
        m.unlockWithPassword(password)
        assertNull(m.errorMessage.value)
        assertEquals(0, settings.appPasswordFailures)
    }

    @Test fun changePasswordKeepsFactorsAndRenewsChallenge() = runBlocking {
        vaultWithFactors()
        val old = lock.factors()
        val key = opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw(), input())).let { v -> v.localKey.copyOf().also { v.close() } }
        controller.change(key, pw(), pw("a brand new pass phrase 8"), input())
        val now = lock.factors()
        assertEquals(old.map { it.kind }, now.map { it.kind })
        assertEquals(old[0], now[0])
        assertNotEquals("the YubiKey answers a new challenge", old[1].challenge, now[1].challenge)
        val last = (now[1].challenge!!.takeLast(2))
        assertTrue(last != "00" && last != "20")
        assertTrue(runCatching { opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw(), input())) }.isFailure)
        opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw("a brand new pass phrase 8"), input())).close()
        key.fill(0)
    }

    @Test fun removingTheLastFactorWritesV1AndAlwaysAskDeletesTheShortcut() = runBlocking {
        vaultWithFactors(biometric = true)
        val key = opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw(), input())).let { v -> v.localKey.copyOf().also { v.close() } }
        assertTrue(lock.biometricOn())
        controller.setAlwaysAsk(true) { settings.factorsAlwaysAsk = it }
        assertFalse("deleted, not just hidden", lock.biometricOn())
        val refused = runCatching { controller.setBiometric(key, true, alwaysAsk = settings.factorsAlwaysAsk) }.exceptionOrNull()
        assertEquals("Turn off “Always ask for the key file / YubiKey” first.", AppLockModel.message(refused!!, txt))
        val recovery = lock.files.record.readBytes().let { it.copyOfRange(it.size - 76, it.size) }
        controller.changeFactors(key, pw(), input(), FactorChange.RemoveYubiKey)
        assertEquals(listOf(FactorKind.KEYFILE), lock.factors().map { it.kind })
        controller.changeFactors(key, pw(), input(), FactorChange.RemoveKeyFile)
        val v1 = lock.files.record.readBytes()
        assertEquals(AppPasswordRecord.SIZE, v1.size)
        assertArrayEquals(recovery, v1.copyOfRange(v1.size - 76, v1.size))
        opener().open(authenticate = { it }, credential = UnlockCredential.Password(pw())).close()
        assertTrue(runCatching { opener().open(authenticate = { it }) }.exceptionOrNull() is AppPasswordRequiredException)
        // A key file added from a file that is not a key file is refused before anything is written.
        val bad = runCatching { controller.changeFactors(key, pw(), null, FactorChange.AddKeyFile("<KeyFile><Key>".toByteArray())) }.exceptionOrNull()
        assertEquals("This file can't be used as a key file.", AppLockModel.message(bad!!, txt))
        assertArrayEquals(v1, lock.files.record.readBytes())
        key.fill(0)
    }

    /** Review fix 1: a picked key file's grant is persisted only after it worked and only when it is remembered. */
    @Test fun keyFileGrantsOnlyAfterSuccess() = runBlocking {
        vaultWithFactors(yubiKey = false)
        val m = lockedModel()
        assertTrue(m.remembersKeyFile())
        // A wrong pick, then the right one: the wrong one is given back, nothing is kept before the unlock.
        val other = KeyFileRef("content://test/other", "other.keyx")
        source.files[other.uri] = KeyFile.keepassXmlV2(ByteArray(32) { 3 })
        m.chooseKeyFile(other, remember = true)
        m.unlockWithPassword(password)
        assertEquals(State.LOCKED, m.state.value)
        assertTrue("failure: no grant persisted", source.rememberCalls.isEmpty())
        m.chooseKeyFile(keyFileRef, remember = true)
        assertEquals(listOf(other), source.releases)
        // A cancelled or failed try (wrong password) keeps nothing either.
        m.unlockWithPassword("not the password")
        assertTrue(source.rememberCalls.isEmpty())
        m.unlockWithPassword(password)
        assertEquals(State.UNLOCKED, m.state.value)
        assertEquals(listOf(keyFileRef), source.rememberCalls)
        m.lock()

        // "Don't remember": no box, nothing kept, and the picked file's grant is given back after use.
        source.remembering = false
        source.remembered = null
        source.rememberCalls.clear(); source.releases.clear()
        m.unlock()
        assertFalse(m.remembersKeyFile())
        m.chooseKeyFile(keyFileRef, remember = false)
        m.unlockWithPassword(password)
        assertEquals(State.UNLOCKED, m.state.value)
        assertTrue(source.rememberCalls.isEmpty())
        assertEquals(listOf(keyFileRef), source.releases)
        m.lock()

        // Unticked on the unlock screen while Settings remembers: used once, then given back.
        source.remembering = true
        source.releases.clear()
        m.unlock()
        m.chooseKeyFile(keyFileRef, remember = false)
        m.unlockWithPassword(password)
        assertTrue(source.rememberCalls.isEmpty())
        assertEquals(listOf(keyFileRef), source.releases)
    }

    /** Review fix 1: the phone's source persists, records and gives back grants (fake content resolver). */
    @Test fun androidSourceKeepsOnlyRecordedGrants() {
        val persisted = mutableListOf<String>()
        val released = mutableListOf<String>()
        var allow = true
        val grants = object : UriGrants {
            override fun persist(uri: String): Boolean { if (allow) persisted += uri; return allow }
            override fun release(uri: String) { released += uri }
        }
        val s = AppSettings(MemoryStore())
        val src = AndroidFactorSource(s, null, grants) { null }
        val a = KeyFileRef("content://a", "a.keyx")
        val b = KeyFileRef("content://b", "b.keyx")
        assertTrue(src.remembers())
        src.rememberKeyFile(a)
        assertEquals(listOf("content://a"), persisted)
        assertEquals(a, src.rememberedKeyFile())
        src.releaseKeyFile(a)
        assertTrue("the recorded file keeps its grant", released.isEmpty())
        src.rememberKeyFile(b)
        assertEquals(listOf("content://a"), released)
        assertEquals(b, src.rememberedKeyFile())
        // Removing the key file gives its grant back.
        src.forget()
        assertEquals(listOf("content://a", "content://b"), released)
        assertNull(src.rememberedKeyFile())
        // A provider that refuses persisted access: nothing is recorded.
        allow = false
        src.rememberKeyFile(a)
        assertNull(src.rememberedKeyFile())
        allow = true
        src.rememberKeyFile(a)
        // "Don't remember" gives the recorded grant back, and later picks take none.
        persisted.clear(); released.clear()
        src.setRemember(false)
        assertEquals(listOf("content://a"), released)
        assertFalse(src.remembers())
        src.rememberKeyFile(b)
        assertTrue(persisted.isEmpty())
        assertNull(src.rememberedKeyFile())
        src.releaseKeyFile(b)
        assertEquals(listOf("content://a", "content://b"), released)
        src.setRemember(true)
        assertTrue(src.remembers())
    }

    @Test fun yubiKeyChecksUseTheVectorSecret() {
        // The fake key in variable mode answers the vector's padded challenge with the vector's response.
        val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set"))
        val cases = app.localgatekeys.core.json.CanonicalJson.parse(File(repo, "tests/vectors/composite_key/cases.json").readBytes()).obj().fields
        val yk = cases.getValue("yubikey").obj().fields
        val padded = app.localgatekeys.core.primitives.Hex.decode(yk.getValue("padded_challenge_hex").str())
        val response = FakeFactorSource.variableModeHmac(yk.getValue("hmac_secret").str().toByteArray(), padded)
        assertEquals(yk.getValue("response_hex").str(), app.localgatekeys.core.primitives.Hex.lower(response))
        assertEquals(yk.getValue("check").str(), CompositeKey.check(CompositeKey.yubikeySecret(response)))
    }
}
