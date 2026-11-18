package app.localgatekeys.android.unlock

import app.localgatekeys.android.duress.DuressVault
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.AppPasswordRequiredException
import app.localgatekeys.android.vault.AppPasswordWaitException
import app.localgatekeys.android.vault.BiometricChangedException
import app.localgatekeys.android.vault.VaultKeyException
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.android.vault.syncDirectory
import app.localgatekeys.core.crypto.AppPasswordException
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.sync.ItemStore
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.crypto.Cipher
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * What one unlock opened: the store, the sealed secret slots and the 32-byte local key they share. A plain class
 * (no copy or component functions). The unlocker that opened it shuts it on lock: [beginClose] at once (no read or
 * write starts or finishes after it, and this key copy is zeroed), then [close] off the main thread.
 */
class UnlockedVault(
    val store: ItemStore,
    val slots: SecretSlots,
    val localKey: ByteArray,
    /**
     * Opened with the duress password (sub-plan 08): the second vault. The app starts no sync and offers no autofill
     * or passkey service for it, and keeps its files in its own folder. Nothing on screen names it.
     */
    val decoy: Boolean = false,
) {
    /** Non-blocking: shuts the write gates of the store and the slots and zeroes this key copy. */
    fun beginClose() {
        (store as? LocalStore)?.beginClose()
        slots.beginClose()
        localKey.fill(0)
    }

    /** Blocking (waits for a running store or slots operation): closes both and zeroes their key copies. */
    fun close() {
        beginClose()
        (store as? AutoCloseable)?.close()
        slots.close()
    }

    /** Never shows key material. */
    override fun toString(): String = "UnlockedVault(store=${store.javaClass.simpleName})"
}

/** Device-owner authentication plus opening the vault. The real one is [SystemUnlocker]; tests use fakes. */
interface Unlocker {
    /** Shows the prompt titled [reason] and opens the vault; throws when it cannot (see [AppLockModel.message]). */
    suspend fun unlock(reason: String): UnlockedVault

    /** Task 7: unlock with [credential] (the app password or the recovery phrase); System is [unlock]. */
    suspend fun unlock(reason: String, credential: UnlockCredential): UnlockedVault = unlock(reason)

    /**
     * The app locked: dismisses a prompt that is showing and shuts every vault this unlocker opened, without
     * blocking the calling (main) thread. The next unlock asks again.
     */
    fun lock()

    /** Shuts only [vault] (an unlock that finished after a lock): no prompt is dismissed, no other vault touched. */
    fun discard(vault: UnlockedVault)
}

/** Where the vault lives: `filesDir/Vault`, the wrapped local key `filesDir/vault-key.bin`, the slots `filesDir/secrets.bin`. */
data class VaultDirs(val vault: File, val wrappedKey: File, val secrets: File) {
    companion object {
        fun under(filesDir: File) = VaultDirs(File(filesDir, "Vault"), File(filesDir, "vault-key.bin"), File(filesDir, "secrets.bin"))
    }
}

/**
 * How an unlock proves the owner. [System]: today's prompt, or the biometric shortcut when the app password is on.
 * [Password] and [Recovery] carry NFC UTF-8 bytes the opener zeroes when it is done.
 */
sealed class UnlockCredential {
    object System : UnlockCredential()
    /** [factors]: the key file and YubiKey when the app password needs them (Task 9). */
    class Password(val bytes: ByteArray, val factors: FactorInput? = null) : UnlockCredential() {
        override fun toString() = "Password"
    }
    /** The 24 words and the new app password to set. The phrase needs no factors, and the new password has none. */
    class Recovery(val phrase: String, val newPassword: ByteArray) : UnlockCredential() {
        override fun toString() = "Recovery"
    }
}

/** The prompt failed or was dismissed. [code] is a `BiometricPrompt.ERROR_*` value. */
class AuthenticationException(val code: Int, message: String = "authentication error $code") : Exception(message)

/** The screen-lock prompt (BiometricPrompt in the app, a lambda in tests). */
interface Authenticator {
    /**
     * Shows the prompt. With a [cipher] (API 30+: a per-use key) the prompt authorises it as a CryptoObject and the
     * authorised cipher is returned; with null (API 29: a 30 s time-bound key) it only authenticates. Throws
     * [AuthenticationException] when dismissed or failed.
     */
    suspend fun authenticate(reason: String, cipher: Cipher?): Cipher?

    /**
     * Task 7: a strong-biometric-only prompt for the app-password shortcut (no screen lock), always with a [cipher];
     * its cancel button reads "Use app password". Fakes default to [authenticate].
     */
    suspend fun authenticateBiometric(reason: String, cipher: Cipher): Cipher? = authenticate(reason, cipher)

    /** Dismisses a prompt that is showing (the app locked meanwhile). */
    fun cancel()
}

/**
 * The unlock rules, free of Android UI: decides first run / open / vault without key with [LocalStore.bootstrap],
 * and never makes a key over existing store files.
 *
 * - First run (no store files, no `vault-key.bin`): (re)creates the Keystore key, generates a 32-byte local key,
 *   wraps it through the prompt-authorised cipher, writes `vault-key.bin` atomically and opens an empty store.
 * - Open (`vault-key.bin` present): unwraps the local key through the prompt. A Keystore key that is gone is a
 *   vault without key; an invalidated one surfaces as `VaultKeyException(INVALIDATED)` (the lock model offers
 *   Start fresh for both).
 * - Vault without key (store files, no `vault-key.bin`): throws `LocalStoreException(VAULT_WITHOUT_KEY)`, no prompt.
 *
 * [cryptoBound] is true on API 30+ (the cipher is made first and authorised by the prompt, so `doFinal` only ever
 * runs after a successful CryptoObject prompt); false on API 29 (prompt first, then the cipher inside the window).
 */
class VaultOpener(
    private val dirs: VaultDirs,
    private val vaultKey: VaultKey,
    private val random: RandomSource,
    private val settings: AppSettings?,
    private val cryptoBound: Boolean,
    /** Task 7: the optional app password. Null or off: today's unlock, unchanged. */
    private val appPassword: AppPasswordLock? = null,
    /**
     * Task 9: "Always ask for the key file / YubiKey" is on. With factors set, the biometric shortcut (which holds the
     * local key without them) is then deleted rather than used.
     */
    private val alwaysAskFactors: () -> Boolean = { false },
    /** Sub-plan 08: the duress password (a second app password); null or not set up: today's unlock. */
    private val duress: DuressVault? = null,
) {
    suspend fun open(
        authenticate: suspend (Cipher?) -> Cipher?,
        credential: UnlockCredential = UnlockCredential.System,
        authenticateBiometric: suspend (Cipher) -> Cipher? = authenticate,
    ): UnlockedVault {
        try {
            val (action, passwordOn) = withContext(Dispatchers.IO) {
                val on = appPassword?.isOn() == true
                LocalStore.bootstrap(dirs.vault, dirs.wrappedKey.exists() || on) to on
            }
            return when (action) {
                LocalStore.Companion.BootstrapAction.VAULT_WITHOUT_KEY ->
                    throw LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
                LocalStore.Companion.BootstrapAction.FIRST_RUN -> {
                    if (credential != UnlockCredential.System) throw AppPasswordRequiredException()
                    firstRun(authenticate)
                }
                LocalStore.Companion.BootstrapAction.OPEN ->
                    if (passwordOn) openWithAppPassword(appPassword!!, credential, authenticateBiometric)
                    else if (credential != UnlockCredential.System) throw IllegalStateException("the app password is off")
                    else openExisting(authenticate)
            }
        } finally {
            when (credential) {
                is UnlockCredential.Password -> credential.bytes.fill(0)
                is UnlockCredential.Recovery -> credential.newPassword.fill(0)
                UnlockCredential.System -> {}
            }
        }
    }

    /**
     * Password mode: the password, the phrase (which also sets the new password) or the biometric-only shortcut.
     * A passcode-capable key left from an interrupted turn-on is deleted once the vault opened.
     */
    private suspend fun openWithAppPassword(
        lock: AppPasswordLock,
        credential: UnlockCredential,
        authenticateBiometric: suspend (Cipher) -> Cipher?,
    ): UnlockedVault {
        val localKey: ByteArray = when (credential) {
            is UnlockCredential.Password -> {
                if (duress != null && withContext(Dispatchers.IO) { duress.configured() }) {
                    return openWithDuress(lock, duress, credential)
                }
                val specs = withContext(Dispatchers.IO) { lock.record().factors }
                if (specs.isEmpty()) {
                    withContext(Dispatchers.IO) { lock.unwrapPassword(credential.bytes) }
                } else {
                    // No touch or file read while the wrong-try delay runs; a wrong factor fails before Argon2id.
                    val wait = withContext(Dispatchers.IO) { lock.waitSeconds() }
                    if (wait > 0) throw AppPasswordWaitException(wait)
                    val secrets = FactorSecrets.collect(specs, credential.factors)
                    try {
                        withContext(Dispatchers.IO) { lock.unwrapPassword(credential.bytes, secrets) }
                    } finally {
                        secrets.forEach { it.fill(0) }
                    }
                }
            }
            is UnlockCredential.Recovery -> withContext(Dispatchers.IO) {
                val previous = lock.failureCount()
                val k = lock.unwrapPhrase(credential.phrase)
                if (duress?.held() == true) {
                    // Held after a duress unlock: the same work, then refused as a wrong phrase and counted on top of
                    // the earlier count (the counted try reset it), so the delay grows as for a wrong phrase.
                    k.fill(0)
                    lock.noteWrongTryAfter(previous)
                    throw AppPasswordException(AppPasswordException.Kind.WRONG_PHRASE, "This recovery phrase does not belong to this vault")
                }
                try {
                    // Sub-plan 08: the new app password must not be the duress password or one edit from it.
                    duress?.checkNewPassword(k, credential.newPassword, decoySession = false)
                } catch (e: Exception) {
                    k.fill(0)
                    throw e
                }
                try {
                    lock.write(lock.record().withNewPassword(k, credential.newPassword, random))
                } catch (e: Exception) {
                    k.fill(0)
                    throw e
                }
                k
            }
            UnlockCredential.System -> {
                // Held after a duress unlock: the fingerprint shortcut is not offered; type the app password.
                if (duress != null && withContext(Dispatchers.IO) { duress.held() }) throw AppPasswordRequiredException()
                val shortcutRemoved = withContext(Dispatchers.IO) {
                    if (lock.biometricOn() && alwaysAskFactors() && lock.factors().isNotEmpty()) {
                        lock.removeBiometric()
                        true
                    } else false
                }
                if (shortcutRemoved || !withContext(Dispatchers.IO) { lock.biometricOn() }) throw AppPasswordRequiredException()
                val (wrapped, cipher) = withContext(Dispatchers.IO) { biometric(lock) { lock.bioCipherForUnwrap() } }
                val authorised = authenticateBiometric(cipher) ?: cipher
                withContext(Dispatchers.IO) { biometric(lock) { lock.bioKey.unwrap(wrapped, authorised) } }
            }
        }
        try {
            return withContext(Dispatchers.IO) {
                try {
                    if (dirs.wrappedKey.exists()) dirs.wrappedKey.delete()
                    if (vaultKey.exists()) vaultKey.delete()
                } catch (e: Exception) {
                    // retried at the next unlock; the password file decides the mode
                }
                openWith(localKey)
            }
        } finally {
            localKey.fill(0)
        }
    }

    /**
     * The app password with a duress password set up (desktop `duress.open_vault`): the real vault first, then the second
     * vault, both Argon2id runs every time so the time taken tells nothing. The real password while the real vault is
     * held is refused as wrong (and counted); the duress password opens the second vault, resets the wrong-try count and
     * holds the real vault for its hours. Anything else is the real vault's own refusal.
     */
    private suspend fun openWithDuress(lock: AppPasswordLock, duress: DuressVault, credential: UnlockCredential.Password): UnlockedVault {
        val wait = withContext(Dispatchers.IO) { lock.waitSeconds() }
        if (wait > 0) throw AppPasswordWaitException(wait)
        val specs = withContext(Dispatchers.IO) { lock.record().factors }
        var failure: Exception? = null
        var realKey: ByteArray? = null
        val secrets = try {
            FactorSecrets.collect(specs, credential.factors)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            failure = e
            null
        }
        // Read before the counted try: a right password refused while held must not reset the count (review I1).
        val previous = withContext(Dispatchers.IO) { lock.failureCount() }
        if (secrets != null) {
            try {
                realKey = withContext(Dispatchers.IO) { lock.unwrapPassword(credential.bytes, secrets) }
            } catch (e: AppPasswordException) {
                failure = e
            } finally {
                secrets.forEach { it.fill(0) }
            }
        }
        val decoyKey = withContext(Dispatchers.IO) { duress.tryOpen(credential.bytes) }
        if (realKey != null) {
            decoyKey?.fill(0)
            val held = withContext(Dispatchers.IO) { duress.held() }
            if (held) {
                realKey.fill(0)
                withContext(Dispatchers.IO) { lock.noteWrongTryAfter(previous) }
                throw AppPasswordException(AppPasswordException.Kind.WRONG_PASSWORD, "That app password is not right")
            }
            try {
                return withContext(Dispatchers.IO) {
                    duress.release()
                    try {
                        if (dirs.wrappedKey.exists()) dirs.wrappedKey.delete()
                        if (vaultKey.exists()) vaultKey.delete()
                    } catch (e: Exception) {
                        // retried at the next unlock; the password file decides the mode
                    }
                    openWith(realKey)
                }
            } finally {
                realKey.fill(0)
            }
        }
        if (decoyKey != null) {
            try {
                return withContext(Dispatchers.IO) {
                    lock.clearFailures()
                    duress.trip(decoyKey)
                    openDecoy(duress, decoyKey)
                }
            } finally {
                decoyKey.fill(0)
            }
        }
        throw failure ?: AppPasswordException(AppPasswordException.Kind.WRONG_PASSWORD, "That app password is not right")
    }

    /** The second vault's store and slots (its own folder); copies [localKey]. */
    private fun openDecoy(duress: DuressVault, localKey: ByteArray): UnlockedVault {
        val d = duress.files.vaultDirs
        val store = LocalStore.open(d.vault, localKey, random, null)
        val slots = try {
            SecretSlots(d.secrets, localKey, random)
        } catch (e: Exception) {
            store.close()
            throw e
        }
        duress.sessionOpen = true
        return UnlockedVault(store, slots, localKey.copyOf(), decoy = true)
    }

    /** An invalidated biometric key (new fingerprint or face): remove the shortcut and ask for the password. */
    private inline fun <T> biometric(lock: AppPasswordLock, block: () -> T): T = try {
        block()
    } catch (e: VaultKeyException) {
        if (e.kind == VaultKeyException.Kind.INVALIDATED || e.kind == VaultKeyException.Kind.MISSING) {
            try { lock.removeBiometric() } catch (x: Exception) {}
            throw BiometricChangedException()
        }
        throw e
    }

    private suspend fun firstRun(authenticate: suspend (Cipher?) -> Cipher?): UnlockedVault {
        withContext(Dispatchers.IO) {
            // No store files and no wrapped key: a Keystore key left here wraps nothing (a first run cancelled at the
            // prompt, or an erase that stopped half way), and secrets.bin is sealed with a local key that is gone.
            if (vaultKey.exists()) vaultKey.delete()
            if (dirs.secrets.exists() && !dirs.secrets.delete()) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "stale secrets")
            }
            vaultKey.create()
        }
        val cipher = authorised(authenticate) { vaultKey.cipherForWrap() }
        val localKey = random.bytes(32)
        try {
            return withContext(Dispatchers.IO) {
                val wrapped = vaultKey.wrap(localKey, cipher)
                writeAtomically(dirs.wrappedKey, wrapped)
                openWith(localKey)
            }
        } finally {
            localKey.fill(0)
        }
    }

    private suspend fun openExisting(authenticate: suspend (Cipher?) -> Cipher?): UnlockedVault {
        val wrapped = withContext(Dispatchers.IO) {
            val bytes = try {
                dirs.wrappedKey.readBytes()
            } catch (e: IOException) {
                throw LocalStoreException(LocalStoreException.Kind.IO, "vault key file")
            }
            // The wrapping key is gone (app data copied to another install, Keystore wiped): the files cannot open.
            if (!vaultKey.exists()) throw LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
            bytes
        }
        val cipher = authorised(authenticate) { vaultKey.cipherForUnwrap(wrapped) }
        return withContext(Dispatchers.IO) {
            val localKey = vaultKey.unwrap(wrapped, cipher)
            try {
                openWith(localKey)
            } finally {
                localKey.fill(0)
            }
        }
    }

    /** API 30+: make the cipher, then the prompt authorises it. API 29: prompt, then make it inside the window. */
    private suspend fun authorised(authenticate: suspend (Cipher?) -> Cipher?, make: () -> Cipher): Cipher =
        if (cryptoBound) {
            val c = withContext(Dispatchers.IO) { make() }
            authenticate(c) ?: c
        } else {
            authenticate(null)
            withContext(Dispatchers.IO) { make() }
        }

    /** Copies [localKey]: the caller zeroes its own array. */
    private fun openWith(localKey: ByteArray): UnlockedVault {
        duress?.sessionOpen = false
        val store = LocalStore.open(dirs.vault, localKey, random, settings)
        val slots = try {
            SecretSlots(dirs.secrets, localKey, random)
        } catch (e: Exception) {
            store.close()
            throw e
        }
        return UnlockedVault(store, slots, localKey.copyOf())
    }

    /** Temp file `.<name>.<random>.tmp`, fsync, atomic rename, directory fsync. */
    private fun writeAtomically(file: File, bytes: ByteArray) {
        val dir = file.absoluteFile.parentFile ?: throw LocalStoreException(LocalStoreException.Kind.IO, "vault key file")
        val tmp = File(dir, ".${file.name}.${Hex.lower(random.bytes(8))}.tmp")
        try {
            dir.mkdirs()
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync()
            }
            try {
                Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                throw IOException("atomic rename not supported", e)
            }
            syncDirectory(dir)
        } catch (e: IOException) {
            tmp.delete()
            throw LocalStoreException(LocalStoreException.Kind.IO, "vault key file")
        }
    }
}

/**
 * [Unlocker] over a [VaultOpener] and an [Authenticator]. Tracks the vaults it opened by identity; [lock] and
 * [discard] shut them at once ([UnlockedVault.beginClose]) and run the blocking [UnlockedVault.close] on
 * [closeContext] (Dispatchers.IO), never on the caller's thread, so a lock never waits for a running commit.
 */
class VaultUnlocker(
    private val opener: VaultOpener,
    private val authenticator: Authenticator,
    private val closeContext: CoroutineContext = Dispatchers.IO,
) : Unlocker {
    private val open = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<UnlockedVault, Boolean>())
    private val closer = CoroutineScope(SupervisorJob() + closeContext)

    override suspend fun unlock(reason: String): UnlockedVault = unlock(reason, UnlockCredential.System)

    override suspend fun unlock(reason: String, credential: UnlockCredential): UnlockedVault {
        val v = opener.open(
            authenticate = { cipher -> authenticator.authenticate(reason, cipher) },
            credential = credential,
            authenticateBiometric = { cipher -> authenticator.authenticateBiometric(reason, cipher) },
        )
        synchronized(open) { open.add(v) }
        return v
    }

    override fun lock() {
        authenticator.cancel()
        val all = synchronized(open) { open.toList().also { open.clear() } }
        all.forEach { shut(it) }
    }

    override fun discard(vault: UnlockedVault) {
        val known = synchronized(open) { open.remove(vault) }
        if (known) shut(vault)
    }

    private fun shut(v: UnlockedVault) {
        v.beginClose()
        closer.launch { v.close() }
    }
}
