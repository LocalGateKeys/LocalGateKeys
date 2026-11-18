package app.localgatekeys.android.autofill

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.TravelMode
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The fill index at rest (spec section 5): AES-256-GCM under an Android Keystore key that needs no user
 * authentication, so the autofill service can list matching titles and usernames while the vault is locked. It holds
 * no secrets. Lives in `noBackupFilesDir`; [erase] removes the file and the key (vault erase).
 */
class FillIndexStore(private val file: File) {
    private val lock = Any()

    private fun key(create: Boolean): SecretKey? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return gen.generateKey()
    }

    /** The stored index; null when there is none or it cannot be opened (the service then offers only "Unlock"). */
    fun read(): FillIndex? = synchronized(lock) {
        try {
            if (!file.isFile) return null
            val blob = file.readBytes()
            if (blob.size < 12 + 16) return null
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key(false) ?: return null, GCMParameterSpec(128, blob, 0, 12))
            c.updateAAD(AAD)
            FillIndex.decode(c.doFinal(blob, 12, blob.size - 12))
        } catch (e: Exception) {
            null
        }
    }

    fun write(index: FillIndex) = synchronized(lock) {
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key(true))
            c.updateAAD(AAD)
            val sealed = c.iv + c.doFinal(index.encode())
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeBytes(sealed)
            if (!tmp.renameTo(file)) {
                file.delete()
                tmp.renameTo(file)
            }
        } catch (e: Exception) {
            // Best effort: without an index the service offers "Unlock LocalGateKeys" only.
        }
    }

    /**
     * Rebuilt from [s], keeping this phone's app pairings to items that still exist; [isPro] (this phone's Pro state now)
     * decides [FillIndex.freeFull]; [travel] null keeps the stored travel mode (set it at unlock and when it changes).
     */
    fun rebuild(s: StoreSnapshot, isPro: Boolean, travel: TravelMode.Setting? = null): Unit = synchronized(lock) {
        // Read and write under one lock, so a rebuild that keeps the stored travel mode never overwrites one that
        // just set it (the unlock's list load and its travel rebuild run at the same time).
        next(read(), s, isPro, travel)?.let { write(it) }
        Unit
    }

    /**
     * Pairs [packageName] with [itemId] (the person chose that login for that app). [isPro] null keeps the stored
     * [FillIndex.freeFull] (a fill adds no item).
     */
    fun pair(s: StoreSnapshot, packageName: String, itemId: String, isPro: Boolean? = null): Unit = synchronized(lock) {
        // No stored index: this phone's travel mode is unknown here, so nothing is written (hidden logins are never
        // listed); the next unlock writes the index with it.
        val current = read() ?: return@synchronized
        val paired = FillIndex.build(s, current.paired(packageName, itemId).apps, isPro, current.travel)
        write(if (isPro == null) paired.copy(freeFull = current.freeFull) else paired)
    }

    companion object {
        /**
         * The index a rebuild writes: [travel] null keeps the stored one's travel mode; with no stored index it is
         * unknown, so nothing is written (null) rather than listing travel-hidden logins (scan A-L2).
         */
        fun next(current: FillIndex?, s: StoreSnapshot, isPro: Boolean, travel: TravelMode.Setting?): FillIndex? {
            val t = travel ?: current?.travel ?: return null
            return FillIndex.build(s, current?.apps ?: emptyMap(), isPro, t)
        }

        private const val ALIAS = "fill-index-v1"
        private val AAD = "LGK-FILL-INDEX-1".toByteArray(Charsets.US_ASCII)
    }

    /** True when the file (and its temp copy) is gone; the key is deleted best effort. */
    fun erase(): Boolean = synchronized(lock) {
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.delete()
        file.delete()
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(ALIAS)
        } catch (e: Exception) {
            // gone already
        }
        !file.exists() && !tmp.exists()
    }
}
