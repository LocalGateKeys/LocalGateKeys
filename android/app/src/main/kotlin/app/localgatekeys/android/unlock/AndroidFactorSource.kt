package app.localgatekeys.android.unlock

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.result.contract.ActivityResultContracts
import app.localgatekeys.android.settings.AppSettings
import app.localgatekeys.core.crypto.KeyFile
import java.io.InputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Persisted read access to a picked document (`takePersistableUriPermission` / `releasePersistableUriPermission`). */
interface UriGrants {
    /** Keeps read access across restarts; false when the provider does not allow it. */
    fun persist(uri: String): Boolean

    /** Gives a persisted grant back; nothing when none is held. */
    fun release(uri: String)

    companion object {
        fun of(context: Context) = object : UriGrants {
            override fun persist(uri: String): Boolean = try {
                context.contentResolver.takePersistableUriPermission(Uri.parse(uri), Intent.FLAG_GRANT_READ_URI_PERMISSION)
                true
            } catch (e: SecurityException) {
                false
            }

            override fun release(uri: String) {
                try {
                    context.contentResolver.releasePersistableUriPermission(Uri.parse(uri), Intent.FLAG_GRANT_READ_URI_PERMISSION)
                } catch (e: Exception) {
                    // not held (any more): nothing to release
                }
            }
        }
    }
}

/**
 * The phone's [FactorSource]: key files through the system file picker's content URIs and YubiKeys through
 * [YubiKeyReader]. A key file is never copied into app storage. A picked file's read grant is persisted only once it
 * has worked (an unlock or a Settings change) and its location is really remembered ([rememberKeyFile]; not with
 * "Don't remember"); every grant that is no longer recorded is given back.
 */
class AndroidFactorSource(
    private val settings: AppSettings,
    private val reader: YubiKeyReader?,
    private val grants: UriGrants,
    private val open: (uri: String) -> InputStream?,
) : FactorSource {
    constructor(context: Context, settings: AppSettings, reader: YubiKeyReader) :
        this(settings, reader, UriGrants.of(context), { uri -> context.contentResolver.openInputStream(Uri.parse(uri)) })

    override fun rememberedKeyFile(): KeyFileRef? {
        val uri = settings.unlockKeyFileUri?.takeIf { it.isNotEmpty() } ?: return null
        return KeyFileRef(uri, settings.unlockKeyFileName)
    }

    override fun remembers(): Boolean = settings.unlockKeyFileUri != ""

    override suspend fun readKeyFile(ref: KeyFileRef): ByteArray = withContext(Dispatchers.IO) {
        val bytes = try {
            open(ref.uri)?.use { readBounded(it, KeyFile.MAX_BYTES) }
        } catch (e: Exception) {
            null
        } ?: throw KeyFileUnreadableException(ref.name)
        if (bytes.size > KeyFile.MAX_BYTES) {
            bytes.fill(0)
            throw KeyFileUnreadableException(ref.name, tooLarge = true)
        }
        bytes
    }

    override fun rememberKeyFile(ref: KeyFileRef) {
        if (!remembers()) return // "Don't remember": no grant is taken
        val old = settings.unlockKeyFileUri
        if (old == ref.uri) return
        if (!grants.persist(ref.uri)) return // the provider keeps no access: nothing worth remembering
        settings.unlockKeyFileUri = ref.uri
        settings.unlockKeyFileName = ref.name
        if (old != null) grants.release(old)
    }

    override fun releaseKeyFile(ref: KeyFileRef) {
        if (ref.uri != settings.unlockKeyFileUri) grants.release(ref.uri)
    }

    override suspend fun yubiKey(slot: Int, challenge: ByteArray): ByteArray =
        reader?.respond(slot, challenge) ?: throw YubiKeyException(YubiKeyException.Code.NO_TRANSPORT, slot)

    override fun cancelYubiKey() {
        reader?.cancel()
    }

    /** Settings › "Remember the key file location": off forgets the file, gives its grant back and remembers none. */
    fun setRemember(on: Boolean) {
        if (on) {
            if (settings.unlockKeyFileUri == "") settings.unlockKeyFileUri = null
            return
        }
        settings.unlockKeyFileUri?.takeIf { it.isNotEmpty() }?.let { grants.release(it) }
        settings.unlockKeyFileUri = ""
        settings.unlockKeyFileName = ""
    }

    /** No key file any more: the remembered one is forgotten and its grant given back ("Don't remember" stays). */
    fun forget() {
        val old = settings.unlockKeyFileUri?.takeIf { it.isNotEmpty() } ?: return
        grants.release(old)
        settings.unlockKeyFileUri = null
        settings.unlockKeyFileName = ""
    }

    companion object {
        /** The document's display name, or its last path segment. */
        fun displayName(context: Context, uri: Uri): String = try {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (e: Exception) {
            null
        } ?: uri.lastPathSegment.orEmpty()

        /**
         * At most [limit] + 1 bytes of [input] into one array (a larger file shows as limit + 1 bytes); the
         * intermediate buffers are zeroed, so no other copy of the key file stays in memory.
         */
        fun readBounded(input: InputStream, limit: Int): ByteArray {
            var buf = ByteArray(64 * 1024)
            var total = 0
            try {
                while (total <= limit) {
                    if (total == buf.size) {
                        val bigger = buf.copyOf(minOf(buf.size * 2, limit + 1).coerceAtLeast(buf.size + 1))
                        buf.fill(0)
                        buf = bigger
                    }
                    val n = input.read(buf, total, minOf(buf.size - total, limit + 1 - total))
                    if (n < 0) break
                    total += n
                }
                return buf.copyOf(total)
            } finally {
                buf.fill(0)
            }
        }
    }
}

/** The system file picker for a key file: openable documents only (no virtual files without a byte stream). */
class OpenKeyFile : ActivityResultContracts.OpenDocument() {
    override fun createIntent(context: Context, input: Array<String>): Intent =
        super.createIntent(context, input).addCategory(Intent.CATEGORY_OPENABLE)
}
