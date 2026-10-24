package app.localgatekeys.android.vault

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM key `lgk.vault` in the Android Keystore. Production keys always require user authentication
 * (biometric or screen lock): [production] is the only public factory and has no switch to turn that off. The
 * no-auth variant exists for device tests only, is `internal` and refuses to work in a non-debuggable app.
 */
class KeystoreVaultKey private constructor(
    private val alias: String,
    private val requireUserAuth: Boolean,
    private val strongBoxFeature: Boolean,
    private val deviceSecure: () -> Boolean,
) : VaultKey {

    private fun store(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun exists(): Boolean = VaultKeyErrors.translate("keystore unavailable") { store().containsAlias(alias) }

    override fun create() {
        if (exists()) throw VaultKeyException(VaultKeyException.Kind.FAILED, "vault key already exists")
        if (requireUserAuth && !deviceSecure()) {
            throw VaultKeyException(VaultKeyException.Kind.NO_SCREEN_LOCK, "no secure lock screen")
        }
        try {
            try {
                generate(strongBox = strongBoxFeature)
            } catch (e: StrongBoxUnavailableException) {
                generate(strongBox = false)
            }
        } catch (e: Exception) {
            // InvalidAlgorithmParameterException (wrapping the "secure lock screen" IllegalStateException),
            // ProviderException ("Keystore key generation failed") and the rest.
            throw VaultKeyErrors.map(e, "key generation failed")
        }
    }

    private fun generate(strongBox: Boolean) {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (requireUserAuth) {
            b.setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= 30) {
                b.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                b.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS_API29)
            }
            b.setInvalidatedByBiometricEnrollment(false)
        }
        if (strongBox) b.setIsStrongBoxBacked(true)
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(b.build())
        gen.generateKey()
    }

    private fun secretKey(): SecretKey = VaultKeyErrors.translate("cannot load vault key") {
        store().getKey(alias, null) as? SecretKey ?: throw VaultKeyException(VaultKeyException.Kind.MISSING, "no vault key")
    }

    private fun init(mode: Int, iv: ByteArray?): Cipher {
        val key = secretKey()
        return VaultKeyErrors.translate("cannot start cipher") {
            val c = Cipher.getInstance(TRANSFORMATION)
            if (iv == null) c.init(mode, key) else c.init(mode, key, GCMParameterSpec(WRAP_TAG_BITS, iv))
            c
        }
    }

    override fun cipherForWrap(): Cipher = init(Cipher.ENCRYPT_MODE, null)

    override fun cipherForUnwrap(wrapped: ByteArray): Cipher {
        val (iv, _) = WrapFormat.split(wrapped)
        return init(Cipher.DECRYPT_MODE, iv)
    }

    override fun wrap(localKey: ByteArray, cipher: Cipher): ByteArray = WrapFormat.wrap(localKey, cipher)

    override fun unwrap(wrapped: ByteArray, cipher: Cipher): ByteArray = WrapFormat.unwrap(wrapped, cipher)

    /**
     * Deletes the key; a key that is already gone is not an error. When the platform has removed the key's blob
     * itself (API 29 deletes auth-bound keys when the screen lock is removed, and a later deleteEntry then fails on
     * the missing blob), the delete counts as done once the alias is provably absent; one retry covers the alias
     * lingering for a moment.
     */
    override fun delete() {
        try {
            deleteOnce()
        } catch (e: VaultKeyException) {
            try {
                deleteOnce()
            } catch (again: VaultKeyException) {
                // fall through to the presence check
            }
            val present = try {
                store().containsAlias(alias)
            } catch (x: Exception) {
                true
            }
            if (present) throw e
        }
    }

    private fun deleteOnce() {
        VaultKeyErrors.translate("cannot delete vault key") {
            val s = store()
            if (s.containsAlias(alias)) s.deleteEntry(alias)
        }
    }

    companion object {
        const val ALIAS = "lgk.vault"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val AUTH_WINDOW_SECONDS_API29 = 30

        /** The production key: always requires user authentication. */
        fun production(context: Context): KeystoreVaultKey {
            val app = context.applicationContext ?: context
            return KeystoreVaultKey(
                ALIAS,
                requireUserAuth = true,
                strongBoxFeature = app.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
                deviceSecure = { (app.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isDeviceSecure == true },
            )
        }

        /**
         * Device tests only: a key under its own alias that needs no user authentication. Refused unless the app
         * is debuggable, so a release build can never make an unauthenticated vault key.
         */
        internal fun forTestingWithoutUserAuth(context: Context, alias: String): KeystoreVaultKey {
            require(alias != ALIAS) { "tests must not touch the production alias" }
            check(isDebuggable(context.applicationInfo.flags)) { "the no-auth vault key is for debuggable builds only" }
            return KeystoreVaultKey(alias, requireUserAuth = false, strongBoxFeature = false, deviceSecure = { true })
        }

        internal fun isDebuggable(applicationFlags: Int): Boolean = (applicationFlags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }
}
