package app.localgatekeys.android.autofill

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.localgatekeys.core.sync.StoreSnapshot
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

    /** Rebuilt from [s], keeping this phone's app pairings to items that still exist. */
    fun rebuild(s: StoreSnapshot) {
        val apps = read()?.apps ?: emptyMap()
        write(FillIndex.build(s, apps))
    }

    /** Pairs [packageName] with [itemId] (the person chose that login for that app). */
    fun pair(s: StoreSnapshot, packageName: String, itemId: String) {
        val current = read() ?: FillIndex.build(s)
        write(FillIndex.build(s, current.paired(packageName, itemId).apps))
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

    private companion object {
        const val ALIAS = "fill-index-v1"
        val AAD = "LGK-FILL-INDEX-1".toByteArray(Charsets.US_ASCII)
    }
}
