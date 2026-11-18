package app.localgatekeys.android.editor

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/**
 * One unsaved editor form (Task 6 of docs/TESTER_FEEDBACK_PLAN_2026-10-29.md): written when the app leaves the screen
 * with the editor open, offered after the next unlock. [itemId] null: a new item. [baseHash] is the SHA-256 of the
 * edited item's record when the editor opened, so a later change (a sync) is noticed. [toString] names fields only.
 */
data class EditorDraft(
    val kind: EditorKind,
    val itemId: String?,
    val baseHash: String?,
    val values: Map<String, String>,
    val createdAt: Long,
) {
    /** What the draft's item looks like now: [Status.SAME_ITEM] reopens it, the others continue as a new item. */
    enum class Status { NEW_ITEM, SAME_ITEM, ITEM_CHANGED, ITEM_DELETED }

    fun status(items: List<VaultItem>): Status {
        val id = itemId ?: return Status.NEW_ITEM
        val item = items.firstOrNull { it.id == id } ?: return Status.ITEM_DELETED
        return if (recordHash(item.record) == baseHash) Status.SAME_ITEM else Status.ITEM_CHANGED
    }

    /**
     * Whether this draft is the form of an editor that reopens by itself after the activity was recreated (dark mode,
     * language, font size) or the process was killed: a new item of [newKind], or the same, unchanged [item]. Anything
     * else is offered with the usual prompt instead.
     */
    fun resumes(newKind: EditorKind?, item: VaultItem?): Boolean = when {
        newKind != null -> itemId == null && kind == newKind
        item != null -> itemId == item.id && baseHash != null && recordHash(item.record) == baseHash
        else -> false
    }

    override fun toString(): String = "EditorDraft(kind=$kind, isNew=${itemId == null}, fields=${values.keys.sorted()})"

    companion object {
        /** Hex SHA-256 of the record's canonical JSON (null when it cannot be encoded). */
        fun recordHash(record: Map<String, JsonValue>): String? = try {
            MessageDigest.getInstance("SHA-256").digest(CanonicalJson.encode(JsonValue.Obj(record), Dialect.UTF8))
                .joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        } catch (_: Exception) {
            null
        }
    }
}

/**
 * The one draft file, sealed with a key derived from the vault's local key: HKDF-SHA256(localKey, salt empty,
 * info "localgatekeys|editor-draft|v1", 32), then AES-256-GCM with a fresh 12-byte nonce and AAD
 * "lgk-editor-draft-v1". File: `nonce || ciphertext+tag`, in noBackupFilesDir. Never plaintext, never in
 * preferences, never logged.
 *
 * [localKey] is the open vault's own array (UnlockedVault.localKey): read at each call, so after a lock (which zeroes
 * it) nothing is written or read. [saveLater] (the editor's ON_STOP) derives the key and takes the (immutable) form
 * on the caller's thread, before the process ON_STOP lock can zero the key, and leaves the sealing and the file write to one
 * background lane; [load] and [delete] wait for that write first, so a reopened editor reads the newest draft and a
 * Save or Discard never leaves a stale one behind.
 */
class EditorDraftStore(
    val file: File,
    private val localKey: ByteArray,
    private val random: RandomSource,
    private val clock: UnixClock,
) {
    /** Replaces the draft (there is only ever one). False when nothing could be written; the old one is gone then too. */
    fun save(draft: EditorDraft): Boolean {
        awaitPending()
        val key = subkey() ?: return false
        return write(key, draft)
    }

    /**
     * [save] without blocking the caller on the encryption and the disk: the key and the form are taken now, the write
     * runs on the background lane. False when the vault is locked (nothing is written).
     */
    fun saveLater(draft: EditorDraft): Boolean {
        val key = subkey() ?: return false
        val task = try {
            LANE.submit { write(key, draft) }
        } catch (_: Exception) {
            return write(key, draft) // the lane is gone (never in practice): write here
        }
        synchronized(LANE) { pending = task }
        return true
    }

    /** Seals and writes [draft] with [key], then zeroes the key. */
    private fun write(key: ByteArray, draft: EditorDraft): Boolean = try {
        val plain = encode(draft)
        try {
            val nonce = random.bytes(NONCE_BYTES)
            val blob = nonce + CryptoBox.sealGcm(key, nonce, plain, AAD)
            val tmp = File(file.parentFile, file.name + ".tmp")
            file.parentFile?.mkdirs()
            tmp.writeBytes(blob)
            if (!tmp.renameTo(file)) {
                file.delete()
                if (!tmp.renameTo(file)) {
                    tmp.delete()
                    false
                } else {
                    true
                }
            } else {
                true
            }
        } finally {
            plain.fill(0)
        }
    } catch (_: Exception) {
        deleteFile(file)
        false
    } finally {
        key.fill(0)
    }

    /** Waits (bounded) for a [saveLater] write still in flight. */
    private fun awaitPending() {
        val task = synchronized(LANE) { pending } ?: return
        try {
            task.get(PENDING_WAIT_MS, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
        }
    }

    /** The draft, or null. One that is expired (7 days), unreadable or sealed with another key is deleted. */
    fun load(): EditorDraft? {
        awaitPending()
        if (!file.exists()) return null
        val key = subkey() ?: return null // locked: leave it for the next unlock
        try {
            val blob = file.readBytes()
            if (blob.size < NONCE_BYTES + 16) { delete(); return null }
            val plain = CryptoBox.openGcm(key, blob.copyOfRange(0, NONCE_BYTES), blob.copyOfRange(NONCE_BYTES, blob.size), AAD)
            val draft = try { decode(plain) } finally { plain.fill(0) }
            val age = clock.now - draft.createdAt
            if (age > MAX_AGE_SECONDS || age < -MAX_AGE_SECONDS) { delete(); return null }
            return draft
        } catch (_: Exception) {
            delete()
            return null
        } finally {
            key.fill(0)
        }
    }

    fun delete(): Boolean {
        awaitPending()
        return deleteFile(file)
    }

    /** The derived key, or null when the vault's key is gone (zeroed by a lock). The caller zeroes it. */
    private fun subkey(): ByteArray? {
        if (localKey.size != 32 || localKey.all { it.toInt() == 0 }) return null
        return CryptoBox.hkdf(localKey, ByteArray(0), INFO, 32)
    }

    override fun toString(): String = "EditorDraftStore"

    companion object {
        const val FILE_NAME = "editor-draft.bin"
        const val MAX_AGE_SECONDS = 7L * 24 * 3600
        private const val NONCE_BYTES = 12
        private val INFO = "localgatekeys|editor-draft|v1".toByteArray(Charsets.UTF_8)
        private val AAD = "lgk-editor-draft-v1".toByteArray(Charsets.UTF_8)
        private const val PENDING_WAIT_MS = 2_000L

        /** One background thread for every draft write, so writes land in order. */
        private val LANE: ExecutorService = Executors.newSingleThreadExecutor { r ->
            Thread(r, "lgk-editor-draft").apply { isDaemon = true }
        }

        /** The last write handed to [LANE] (shared: a recreated activity's store waits for the old one's write). */
        private var pending: Future<*>? = null

        /** Where the draft lives: the app's noBackupFilesDir. */
        fun file(noBackupDir: File): File = File(noBackupDir, FILE_NAME)

        /** True when the file (and its temp copy) are gone. Erase, Leave and Reset use it without a key. */
        fun deleteFile(file: File): Boolean {
            val tmp = File(file.parentFile, file.name + ".tmp")
            if (tmp.exists()) tmp.delete()
            return !file.exists() || file.delete() || !file.exists()
        }

        internal fun encode(d: EditorDraft): ByteArray = CanonicalJson.encode(
            JsonValue.Obj(
                mapOf(
                    "v" to JsonValue.Int(1),
                    "kind" to JsonValue.Str(d.kind.raw),
                    "item_id" to (d.itemId?.let { JsonValue.Str(it) } ?: JsonValue.Null),
                    "base_hash" to (d.baseHash?.let { JsonValue.Str(it) } ?: JsonValue.Null),
                    "values" to JsonValue.Obj(d.values.mapValues { JsonValue.Str(it.value) }),
                    "created_at" to JsonValue.Int(d.createdAt),
                ),
            ),
            Dialect.UTF8,
        )

        internal fun decode(b: ByteArray): EditorDraft {
            val o = (CanonicalJson.parse(b) as JsonValue.Obj).fields
            require((o["v"] as JsonValue.Int).v == 1L)
            val kind = EditorKind.of((o["kind"] as JsonValue.Str).v) ?: throw IllegalArgumentException("kind")
            val values = (o["values"] as JsonValue.Obj).fields.mapValues { (it.value as JsonValue.Str).v }
            return EditorDraft(
                kind = kind,
                itemId = (o["item_id"] as? JsonValue.Str)?.v,
                baseHash = (o["base_hash"] as? JsonValue.Str)?.v,
                values = values,
                createdAt = (o["created_at"] as JsonValue.Int).v,
            )
        }
    }
}

/** The prompt after unlock. */
object EditorDraftText {
    @StringRes val TITLE = R.string.draft_title
    @StringRes val CONTINUE = R.string.draft_continue
    @StringRes val DISCARD = R.string.draft_discard
    fun message(status: EditorDraft.Status, kind: EditorKind, t: Txt): String = when (status) {
        EditorDraft.Status.NEW_ITEM, EditorDraft.Status.SAME_ITEM -> t.s(R.string.draft_left_app, kind.label(t))
        EditorDraft.Status.ITEM_CHANGED -> t.s(R.string.draft_item_changed)
        EditorDraft.Status.ITEM_DELETED -> t.s(R.string.draft_item_deleted)
    }
}
