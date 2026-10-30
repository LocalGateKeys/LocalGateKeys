package app.localgatekeys.android.share

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import androidx.annotation.StringRes
import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.pro.ProFeatures
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.share.OpenedShare
import app.localgatekeys.core.share.Share
import app.localgatekeys.core.share.ShareException
import app.localgatekeys.core.share.ShareHeader
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import java.io.File
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

// UX workstream 9, secure local sharing (`docs/formats/LGKSHARE_V1.md`; format core in lgk-core `Share`). Nothing here
// logs or prints an item, a code or a package: toString names ids only.

object ShareText {
    @StringRes val SHARE = R.string.detail_pane_share
    @StringRes val SHEET_TITLE = R.string.share_sheet_title
    @StringRes val CODE_TITLE = R.string.share_code_title
    @StringRes val CODE_HINT = R.string.share_code_hint
    @StringRes val SEND_FILE = R.string.share_send_file
    @StringRes val SHOW_QR = R.string.share_show_qr
    @StringRes val QR_TOO_LARGE = R.string.share_qr_too_large
    @StringRes val QR_HINT = R.string.share_qr_hint
    @StringRes val NOT_SHAREABLE = R.string.share_not_shareable
    @StringRes val FAILED = R.string.share_failed

    @StringRes val RECEIVE = R.string.share_receive
    @StringRes val RECEIVE_FOOTER = R.string.share_receive_footer
    @StringRes val SCAN = R.string.command_scan_qr_title
    @StringRes val OPEN_FILE = R.string.share_open_file
    @StringRes val FROM = R.string.share_from
    @StringRes val CODE_LABEL = R.string.incoming_sheet_code
    @StringRes val OPEN = R.string.incoming_sheet_open
    @StringRes val ADD = R.string.share_add
    @StringRes val REJECT = R.string.incoming_sheet_reject
    @StringRes val ADDED = R.string.share_added
    @StringRes val CANNOT_SAVE = R.string.share_cannot_save
    @StringRes val TOO_MANY = R.string.share_too_many
    @StringRes val NOT_A_SHARE_QR = R.string.share_not_a_share_qr

    fun needsPro(t: Txt): String = t.plural(R.plurals.share_needs_pro, ItemLimit.FREE_ITEMS, ItemLimit.FREE_ITEMS)

    fun attemptsLeft(n: Int, t: Txt): String = t.plural(R.plurals.share_attempts_left, n, n)

    /** A refused share in the person's language, by the core's case code (the core's English is for logs and tests). */
    fun refusal(e: ShareException, t: Txt): String = t.s(
        when (e.code) {
            "need-six-words" -> R.string.share_enter_the_six_words_of
            "not-saved" -> R.string.share_only_asaved_item_can
            "passkeys-attachments", "passkeys-files" -> R.string.share_passkeys_and_attachments_cannot_be
            "too-large" -> R.string.share_this_item_is_too_large2
            "damaged" -> R.string.share_the_shared_item_is_damaged
            "not-a-share" -> R.string.share_this_is_not_ashared
            "unsupported" -> R.string.share_this_item_was_shared_by
            "already-opened" -> R.string.share_this_shared_item_was_already
            "wrong-code" -> R.string.share_that_code_does_not_open
            "future-date" -> R.string.share_the_shared_item_has_a
            "expired" -> R.string.share_this_shared_item_expired_ask
            "content-not-shareable" -> R.string.share_this_shared_item_holds_content
            "not-a-share-qr" -> R.string.share_this_qr_code_is_not
            "gone" -> R.string.share_refusal_gone
            else -> R.string.share_failed
        },
    )
}

/** One sealed item ready to send. [code] is shown on screen only; [bytes] is the package (file or QR content). */
class OutgoingShare(val bytes: ByteArray, val code: String) {
    val fitsQr: Boolean get() = Share.fitsQr(bytes)
    val qrText: String get() = bytes.toString(Charsets.UTF_8)
    val fileName: String get() = "shared-item.${Share.FILE_EXTENSION}"
    override fun toString(): String = "OutgoingShare(size=${bytes.size})"
}

object ItemSharing {
    const val MIME = "application/octet-stream"

    /** Documents carry a file and passkeys a private key: neither travels in v1. */
    fun canShare(item: VaultItem): Boolean =
        item.kind != "document" && Share.isShareable(JsonValue.Obj(item.record))

    /** Seals [item] under a fresh code. Throws [ShareException] (`not-shareable`, `too-large`). */
    fun prepare(item: VaultItem, clock: UnixClock, random: RandomSource, sender: String = SyncWording.DEVICE_NAME): OutgoingShare {
        if (item.kind == "document") throw ShareException("not-shareable", "Passkeys and files cannot be shared.", "passkeys-files")
        val code = Share.generateCode(random)
        return OutgoingShare(Share.seal(withoutLocalRefs(JsonValue.Obj(item.record)), code, sender, clock.now, random), code)
    }

    private val LOCAL_TRUST_SCOPE_KEYS = listOf(
        "sign_in_selector", "embedded_web_fill_approved", "browser_approval", "browser_approvals", "sync_pairing",
        "pairing_secret", "pairing_state",
    )

    /** What only means something in one vault: linked document ids, a card's billing identity, trust approvals. */
    fun withoutLocalRefs(item: JsonValue.Obj): JsonValue.Obj {
        val rec = LinkedHashMap(item.fields)
        (rec["payload"] as? JsonValue.Obj)?.let { p ->
            val payload = LinkedHashMap(p.fields)
            if ("document_ids" in payload) payload["document_ids"] = JsonValue.Arr(emptyList())
            if ((payload["billing_address_id"] as? JsonValue.Str)?.v?.isNotEmpty() == true) payload["billing_address_id"] = JsonValue.Str("")
            rec["payload"] = JsonValue.Obj(payload)
        }
        (rec["scope"] as? JsonValue.Obj)?.let { sc -> rec["scope"] = JsonValue.Obj(sc.fields.filterKeys { it !in LOCAL_TRUST_SCOPE_KEYS }) }
        return JsonValue.Obj(rec)
    }

    enum class SaveOutcome { SAVED, NEEDS_PRO, INVALID }

    /**
     * Saves an opened item as a new item: a fresh id and timestamps, not a favorite, policies left to this phone's
     * defaults (the share never carries them), checked by `Normalise` like an edit, and counted against the free limit.
     */
    fun save(opened: OpenedShare, store: ItemStore, isPro: Boolean, clock: UnixClock, random: RandomSource): SaveOutcome {
        // The stored shape (spec), also from early builds that sent top-level `urls` / `fields`.
        val fields = LinkedHashMap(withoutLocalRefs(Share.storedForm(opened.item)).fields)
        val kind = (fields["kind"] as? JsonValue.Str)?.v ?: return SaveOutcome.INVALID
        // Desktop logins (and passkeys) are not kept on a phone.
        if (kind == "passkey" || (kind !in Normalise.phoneEntryKinds && kind !in Normalise.phoneItemKinds)) return SaveOutcome.INVALID
        val now = clock.now
        fields["id"] = JsonValue.Str(EditorModel.uuid4(random))
        fields["created_at"] = JsonValue.Int(now)
        fields["updated_at"] = JsonValue.Int(now)
        fields["favorite"] = JsonValue.Bool(false)
        val ns = if (kind == "web") Namespace.ENTRY else Namespace.ITEM
        val record = try {
            Normalise.normalForm(ns, JsonValue.Obj(fields))
        } catch (e: Exception) {
            return SaveOutcome.INVALID
        }
        val id = ((record as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v ?: return SaveOutcome.INVALID
        val snap = store.load()
        if (!ItemLimit.allows(ItemLimit.Action.CREATE, snap, isPro)) return SaveOutcome.NEEDS_PRO
        if (!isPro && ProFeatures.totpChangeNeedsPro((record as JsonValue.Obj).fields["totp"], null)) return SaveOutcome.NEEDS_PRO
        if (snap.records[id] != null) return SaveOutcome.INVALID
        val records = LinkedHashMap(snap.records)
        records[id] = Wrapper.make(ns, record)
        store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
        return SaveOutcome.SAVED
    }

    /** The preview rows: kind and title, then the field names (never values). */
    fun previewTitle(item: JsonValue.Obj, t: Txt): String {
        val f = item.fields
        val title = (f["label"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() } ?: (f["title"] as? JsonValue.Str)?.v.orEmpty()
        return title.ifEmpty { VaultItem.kindLabel((f["kind"] as? JsonValue.Str)?.v.orEmpty(), t) }
    }

    fun previewUser(item: JsonValue.Obj): String? = (item.fields["username"] as? JsonValue.Str)?.v?.takeIf { it.isNotEmpty() }

    fun kindLabel(item: JsonValue.Obj, t: Txt): String = VaultItem.kindLabel((item.fields["kind"] as? JsonValue.Str)?.v.orEmpty(), t)
}

/**
 * Received packages and the open-once list, in the app's private storage (never backed up). A delivered file is copied
 * into [dir] at once; each copy is deleted after Add or Reject, after three wrong codes, and once it is older than a day
 * ([purge], at start). [openedFile] holds the ids opened on this phone, kept two days (a package lives one).
 */
class ShareInbox(private val dir: File, private val openedFile: File, private val clock: UnixClock) {
    /** One received package waiting for its code. */
    class Pending internal constructor(val header: ShareHeader, internal val file: File?) {
        var wrongCodes: Int = 0
            internal set
        override fun toString(): String = "ShareInbox.Pending(id=${header.id})"
    }

    /** The package bytes of each pending package (zeroed when it goes). */
    private val memory = HashMap<Pending, ByteArray>()
    private val _pending = MutableStateFlow<Pending?>(null)
    val pending: StateFlow<Pending?> = _pending.asStateFlow()

    /**
     * A delivered package (file bytes or QR text). Checks the clear header first (`malformed`, `unsupported`), then
     * keeps a private copy. Replaces any earlier pending package (whose copy is deleted).
     */
    @Synchronized
    fun accept(data: ByteArray, keepFile: Boolean): Pending {
        val header = Share.readHeader(data)
        discardLocked()
        val file = if (keepFile) {
            if (!dir.mkdirs() && !dir.isDirectory) throw java.io.IOException("inbox")
            File(dir, UUID.randomUUID().toString() + "." + Share.FILE_EXTENSION).also { it.writeBytes(data) }
        } else {
            null
        }
        val p = Pending(header, file)
        memory[p] = data.copyOf()
        _pending.value = p
        return p
    }

    /** The pending package left from an earlier run (a file delivered before the unlock). */
    @Synchronized
    fun restore() {
        if (_pending.value != null) return
        val newest = dir.listFiles()?.filter { it.isFile }?.maxByOrNull { it.lastModified() } ?: return
        try {
            val data = newest.readBytes()
            val p = Pending(Share.readHeader(data), newest)
            memory[p] = data
            _pending.value = p
        } catch (e: Exception) {
            newest.delete()
        }
    }

    /** Opens the pending package. A wrong code counts; the third deletes it ([ShareException] `wrong-code`). */
    @Synchronized
    fun open(p: Pending, code: String): OpenedShare {
        val data = memory[p] ?: throw ShareException("malformed", "The shared item is no longer here.", "gone")
        try {
            return Share.open(data, code, clock.now, openedIds())
        } catch (e: ShareException) {
            when (e.reason) {
                "wrong-code" -> {
                    p.wrongCodes += 1
                    // Burned: the same package delivered again is refused, so the count cannot be reset.
                    if (p.wrongCodes >= MAX_WRONG_CODES) opened(p)
                }
                "already-opened", "expired", "malformed", "unsupported", "not-shareable" -> discard(p)
            }
            throw e
        }
    }

    /** After Add: the id joins the opened list and the package is deleted. */
    @Synchronized
    fun opened(p: Pending) {
        val now = clock.now
        val ids = readOpened().filterValues { now - it < KEEP_OPENED_SECONDS }.toMutableMap()
        ids[p.header.id] = now
        writeOpened(ids)
        discard(p)
    }

    /** Reject, three wrong codes, or a refusal: the package and its copy go. */
    @Synchronized
    fun discard(p: Pending) {
        if (_pending.value === p) _pending.value = null
        memory.remove(p)?.fill(0)
        p.file?.delete()
    }

    private fun discardLocked() {
        _pending.value?.let { discard(it) }
    }

    /** Deletes copies older than a day (their packages have expired) and drops old opened ids. */
    @Synchronized
    fun purge() {
        val cutoff = (clock.now - Share.LIFETIME) * 1000
        dir.listFiles()?.forEach { if (it.lastModified() < cutoff) it.delete() }
        val now = clock.now
        val ids = readOpened()
        val kept = ids.filterValues { now - it < KEEP_OPENED_SECONDS }
        if (kept.size != ids.size) writeOpened(kept)
    }

    /** Erase / reset: everything received goes. */
    @Synchronized
    fun clear() {
        _pending.value?.let { discard(it) }
        dir.deleteRecursively()
        openedFile.delete()
    }

    fun openedIds(): Set<String> = readOpened().keys

    private fun readOpened(): Map<String, Long> = try {
        if (!openedFile.isFile) emptyMap() else {
            (CanonicalJson.parse(openedFile.readBytes()) as JsonValue.Obj).fields.mapValues { (it.value as JsonValue.Int).v }
        }
    } catch (e: Exception) {
        emptyMap()
    }

    private fun writeOpened(ids: Map<String, Long>) {
        val tmp = File(openedFile.parentFile, openedFile.name + ".tmp")
        tmp.writeBytes(CanonicalJson.encode(JsonValue.Obj(ids.mapValues { JsonValue.Int(it.value) }), Dialect.UTF8))
        if (!tmp.renameTo(openedFile)) {
            openedFile.delete()
            tmp.renameTo(openedFile)
        }
    }

    override fun toString(): String = "ShareInbox(pending=${_pending.value != null})"

    companion object {
        const val MAX_WRONG_CODES = 3
        const val KEEP_OPENED_SECONDS = 2 * 24 * 3600L
    }
}
