package app.localgatekeys.android.unlock

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.vault.AppPasswordLock
import app.localgatekeys.android.vault.VaultKey
import app.localgatekeys.android.vault.writeFileAtomically
import app.localgatekeys.android.vault.AppPasswordWaitException
import app.localgatekeys.core.crypto.AppPasswordParams
import app.localgatekeys.core.crypto.AppPasswordRecord
import app.localgatekeys.core.crypto.CompositeKey
import app.localgatekeys.core.crypto.FactorKind
import app.localgatekeys.core.crypto.FactorSpec
import app.localgatekeys.core.crypto.KeyFile
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

    /**
     * The current password (and the key file / YubiKey it needs, from [factors]) must open the file; then only the
     * password wrapper is replaced. The factors stay; a YubiKey gets a new challenge (one more touch).
     */
    suspend fun change(localKey: ByteArray, current: ByteArray, newPassword: ByteArray, factors: FactorInput? = null) {
        try {
            rewrap(localKey, current, factors, newPassword) { specs, secrets -> renewed(specs, secrets, factors) }
        } finally {
            current.fill(0); newPassword.fill(0)
        }
    }

    /** What Settings changes about the factors ([changeFactors]). */
    sealed class FactorChange {
        /** A key file's bytes (the caller zeroes them); replaces a key file already set. */
        class AddKeyFile(val bytes: ByteArray) : FactorChange()
        class AddYubiKey(val slot: Int) : FactorChange()
        object RemoveKeyFile : FactorChange()
        object RemoveYubiKey : FactorChange()
    }

    /**
     * Adds or removes a key file or YubiKey. The current password and today's factors (from [factors]) must open the
     * file; the new password wrapper uses the same password and the new list (no factors left: v1 again). The recovery
     * wrapper never changes. A YubiKey that stays or is added answers a new challenge. Returns the new list.
     */
    suspend fun changeFactors(localKey: ByteArray, current: ByteArray, factors: FactorInput?, change: FactorChange): List<FactorSpec> {
        try {
            return rewrap(localKey, current, factors, null) { specs, secrets ->
                val keep = specs.zip(secrets).filter { (spec, _) ->
                    when (change) {
                        is FactorChange.AddKeyFile, FactorChange.RemoveKeyFile -> spec.kind != FactorKind.KEYFILE
                        is FactorChange.AddYubiKey, FactorChange.RemoveYubiKey -> spec.kind != FactorKind.YUBIKEY_HMAC
                    }
                }
                val added = when (change) {
                    is FactorChange.AddKeyFile -> {
                        val secret = withContext(Dispatchers.Default) { KeyFile.keyFromBytes(change.bytes) }
                        listOf(FactorSpec.keyFile(CompositeKey.check(secret)) to secret)
                    }
                    is FactorChange.AddYubiKey -> {
                        val input = factors ?: throw YubiKeyException(YubiKeyException.Code.NO_TRANSPORT, change.slot)
                        listOf(FactorSecrets.newYubiKey(change.slot, CompositeKey.newChallenge(random), input))
                    }
                    else -> emptyList()
                }
                // A YubiKey that stays answers a new challenge; the list is always key file, then YubiKey.
                val merged = (keep + added).sortedBy { it.first.kind.ordinal }
                try {
                    renewed(merged.map { it.first }, merged.map { it.second }, factors, skip = added.map { it.first })
                } finally {
                    added.forEach { it.second.fill(0) }
                }
            }
        } finally {
            current.fill(0)
        }
    }

    /**
     * Checks [current] with today's factors, then writes a new password wrapper for [newPassword] (null: the same) with
     * the list [next] builds from today's specs and secrets. Every secret is zeroed afterwards.
     */
    private suspend fun rewrap(
        localKey: ByteArray,
        current: ByteArray,
        factors: FactorInput?,
        newPassword: ByteArray?,
        next: suspend (List<FactorSpec>, List<ByteArray>) -> Pair<List<FactorSpec>, List<ByteArray>>,
    ): List<FactorSpec> {
        val record = withContext(Dispatchers.IO) { lock.record() }
        val wait = withContext(Dispatchers.IO) { lock.waitSeconds() }
        if (wait > 0) throw AppPasswordWaitException(wait)
        val secrets = FactorSecrets.collect(record.factors, factors)
        var built: Pair<List<FactorSpec>, List<ByteArray>>? = null
        try {
            withContext(Dispatchers.IO) { lock.unwrapPassword(current, secrets).fill(0) }
            val (specs, newSecrets) = next(record.factors, secrets).also { built = it }
            withContext(Dispatchers.IO) {
                lock.write(lock.record().withNewPassword(localKey, newPassword ?: current, random, factors = specs, secrets = newSecrets))
            }
            return specs
        } finally {
            secrets.forEach { it.fill(0) }
            built?.second?.forEach { it.fill(0) }
        }
    }

    /** [specs] with each YubiKey (except those in [skip], just made) answering a new challenge. */
    private suspend fun renewed(
        specs: List<FactorSpec>,
        secrets: List<ByteArray>,
        factors: FactorInput?,
        skip: List<FactorSpec> = emptyList(),
    ): Pair<List<FactorSpec>, List<ByteArray>> {
        val outSpecs = ArrayList<FactorSpec>()
        val outSecrets = ArrayList<ByteArray>()
        try {
            for ((spec, secret) in specs.zip(secrets)) {
                if (spec.kind == FactorKind.YUBIKEY_HMAC && spec !in skip) {
                    val input = factors ?: throw YubiKeyException(YubiKeyException.Code.NO_TRANSPORT, spec.slot ?: YubiKeyException.DEFAULT_SLOT)
                    val (fresh, freshSecret) = FactorSecrets.newYubiKey(spec.slot ?: YubiKeyException.DEFAULT_SLOT, CompositeKey.newChallenge(random), input)
                    outSpecs += fresh; outSecrets += freshSecret
                } else {
                    outSpecs += spec; outSecrets += secret.copyOf()
                }
            }
        } catch (e: Throwable) {
            outSecrets.forEach { it.fill(0) } // a touch failed half way: the copies made so far go
            throw e
        }
        return outSpecs to outSecrets
    }

    /** "Always ask for the key file / YubiKey" on deletes the fingerprint shortcut (it opens without the factors). */
    suspend fun setAlwaysAsk(on: Boolean, store: (Boolean) -> Unit) = withContext(Dispatchers.IO) {
        if (on) {
            if (lock.factors().isEmpty()) throw FactorSettingsException(FactorSettingsException.Reason.NEEDS_FACTOR)
            lock.removeBiometric()
        }
        store(on)
    }

    /**
     * Turn off: the current password, then a new passcode-capable key wraps the local key (one system prompt), then the
     * shortcut and finally the password file are removed. Throws when the password is wrong or the prompt is cancelled
     * (nothing changed then, apart from a key that wraps nothing yet).
     */
    suspend fun turnOff(localKey: ByteArray, current: ByteArray, reason: String, factors: FactorInput? = null) {
        try {
            val specs = withContext(Dispatchers.IO) { lock.record().factors }
            val secrets = FactorSecrets.collect(specs, factors)
            try {
                withContext(Dispatchers.IO) { lock.unwrapPassword(current, secrets).fill(0) }
            } finally {
                secrets.forEach { it.fill(0) }
            }
        } finally {
            current.fill(0)
        }
        withContext(Dispatchers.IO) {
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

    /**
     * The biometric-only shortcut on (one strong-biometric prompt) or off. [alwaysAsk]: "Always ask for the key file /
     * YubiKey" is on, so with factors set the shortcut is refused.
     */
    suspend fun setBiometric(localKey: ByteArray, on: Boolean, reason: String = t.s(R.string.unlock_use_fingerprint), alwaysAsk: Boolean = false) {
        if (!on) {
            withContext(Dispatchers.IO) { lock.removeBiometric() }
            return
        }
        if (alwaysAsk && withContext(Dispatchers.IO) { lock.factors().isNotEmpty() }) {
            throw FactorSettingsException(FactorSettingsException.Reason.ALWAYS_ASK_ON)
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

/** A factor setting that cannot change as asked (its message says why). */
class FactorSettingsException(val reason: Reason) : Exception(reason.name) {
    enum class Reason { NEEDS_FACTOR, ALWAYS_ASK_ON }
}
