package app.localgatekeys.android.unlock

import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.LocalStoreException
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.android.vault.syncDirectory
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
class UnlockedVault(val store: ItemStore, val slots: SecretSlots, val localKey: ByteArray) {
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
) {
    suspend fun open(authenticate: suspend (Cipher?) -> Cipher?): UnlockedVault {
        val action = withContext(Dispatchers.IO) { LocalStore.bootstrap(dirs.vault, dirs.wrappedKey.exists()) }
        return when (action) {
            LocalStore.Companion.BootstrapAction.VAULT_WITHOUT_KEY ->
                throw LocalStoreException(LocalStoreException.Kind.VAULT_WITHOUT_KEY)
            LocalStore.Companion.BootstrapAction.FIRST_RUN -> firstRun(authenticate)
            LocalStore.Companion.BootstrapAction.OPEN -> openExisting(authenticate)
        }
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

    override suspend fun unlock(reason: String): UnlockedVault {
        val v = opener.open { cipher -> authenticator.authenticate(reason, cipher) }
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
