package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.android.vault.writeFileAtomically
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.primitives.RandomSource
import javax.crypto.Cipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Settings > Security for the app password (Task 7), while the vault is unlocked. Every call takes a copy of the open
 * vault's local key (the caller zeroes it) and the typed passwords as NFC UTF-8 bytes, which are zeroed here.
 *
 * Turn on is two steps so the phrase is shown and confirmed before anything changes on disk: [prepare] (Argon2id, no
 * disk), then [commit] (password file, optional biometric shortcut, then the passcode-capable key is deleted).
 */
class AppPasswordController(
    private val dirs: VaultDirs,
    private val systemKey: VaultKey,
    val lock: AppPasswordLock,
    private val random: RandomSource,
    private val authenticator: Authenticator,
    /** API 30+: the system key's cipher is authorised by the prompt (see [VaultOpener]). */
    private val cryptoBound: Boolean,
    private val t: Txt,
    /** The desktop vault's Argon2id cost; tests pass a cheaper one. */
    private val params: AppPasswordParams = AppPasswordParams.DESKTOP,
) {
    suspend fun isOn(): Boolean = withContext(Dispatchers.IO) { lock.isOn() }

    suspend fun biometricOn(): Boolean = withContext(Dispatchers.IO) { lock.biometricOn() }

    /** Step 1 of turning on: the record and the phrase to show. Nothing is written. */
    suspend fun prepare(localKey: ByteArray, password: ByteArray): AppPasswordRecord.Created = withContext(Dispatchers.IO) {
        try {
            AppPasswordRecord.create(localKey, password, random, params)
        } finally {
            password.fill(0)
        }
    }

    /**
     * Step 2, after the phrase was confirmed. The password file first (from then on the app is in password mode), the
     * biometric shortcut if asked (a cancelled prompt leaves password-only; returns false), then the passcode-capable
     * key and `vault-key.bin` are deleted.
     */
    suspend fun commit(created: AppPasswordRecord.Created, localKey: ByteArray, biometric: Boolean): Boolean {
        withContext(Dispatchers.IO) { lock.write(created.record) }
        var bioDone = !biometric
        if (biometric) {
            bioDone = try {
                setBiometric(localKey, true)
                true
            } catch (e: kotlinx.coroutines.CancellationException) {
                withContext(kotlinx.coroutines.NonCancellable + Dispatchers.IO) { deleteSystemKey() }
                throw e
            } catch (e: Exception) {
                false
            }
        }
        withContext(Dispatchers.IO) { deleteSystemKey() }
        return bioDone
    }

    /** The current password must open the file; then only the password wrapper is replaced. */
    suspend fun change(localKey: ByteArray, current: ByteArray, newPassword: ByteArray) = withContext(Dispatchers.IO) {
        try {
            lock.unwrapPassword(current).fill(0)
            lock.write(lock.record().withNewPassword(localKey, newPassword, random))
        } finally {
            current.fill(0); newPassword.fill(0)
        }
    }

    /**
     * Turn off: the current password, then a new passcode-capable key wraps the local key (one system prompt), then the
     * shortcut and finally the password file are removed. Throws when the password is wrong or the prompt is cancelled
     * (nothing changed then, apart from a key that wraps nothing yet).
     */
    suspend fun turnOff(localKey: ByteArray, current: ByteArray, reason: String) {
        withContext(Dispatchers.IO) {
            try { lock.unwrapPassword(current).fill(0) } finally { current.fill(0) }
            if (systemKey.exists()) systemKey.delete()
            systemKey.create()
        }
        val cipher = if (cryptoBound) {
            val c = withContext(Dispatchers.IO) { systemKey.cipherForWrap() }
            authenticator.authenticate(reason, c) ?: c
        } else {
            authenticator.authenticate(reason, null)
            withContext(Dispatchers.IO) { systemKey.cipherForWrap() }
        }
        withContext(Dispatchers.IO) {
            writeFileAtomically(dirs.wrappedKey, systemKey.wrap(localKey, cipher), random)
            lock.deleteAll()
        }
    }

    /** The biometric-only shortcut on (one strong-biometric prompt) or off. */
    suspend fun setBiometric(localKey: ByteArray, on: Boolean, reason: String = t.s(R.string.unlock_use_fingerprint)) {
        if (!on) {
            withContext(Dispatchers.IO) { lock.removeBiometric() }
            return
        }
        val cipher: Cipher = withContext(Dispatchers.IO) { lock.prepareBiometric() }
        try {
            val authorised = authenticator.authenticateBiometric(reason, cipher) ?: cipher
            withContext(Dispatchers.IO) { lock.finishBiometric(localKey, authorised) }
        } catch (e: Exception) {
            withContext(Dispatchers.IO) { try { lock.removeBiometric() } catch (x: Exception) {} }
            throw e
        }
    }

    /**
     * Blocking, at app start before any prompt: with the password on, a passcode-capable key or `vault-key.bin` left
     * by an interrupted turn-on is deleted. Nothing happens while the password is off.
     */
    fun finishTurnOn() {
        if (!lock.isOn()) return
        if (dirs.wrappedKey.exists()) dirs.wrappedKey.delete()
        if (systemKey.exists()) systemKey.delete()
    }

    private fun deleteSystemKey() {
        dirs.wrappedKey.delete()
        systemKey.delete()
    }
}
