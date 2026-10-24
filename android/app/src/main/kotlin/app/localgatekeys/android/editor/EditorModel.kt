package app.localgatekeys.android.editor

import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.pro.ProFeatures
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.NormaliseException
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.totp.Totp
import app.localgatekeys.core.totp.TotpConfig
import app.localgatekeys.core.totp.TotpException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class SaveResult { SAVED, UNCHANGED, NEEDS_PRO, NEEDS_PUNYCODE, INVALID, FAILED }

/** What the editor shows. [values] holds the form, secrets included: [toString] names the fields only. */
data class EditorState(
    val values: Map<String, String>,
    val error: String? = null,
    val needsPunycode: Boolean = false,
    /** Inline error for the 2FA secret field. */
    val totpError: String? = null,
    /** Inline error for the Website field (`WebsiteInput` wording, never the normaliser's). */
    val websiteError: String? = null,
    /** Inline error for the Amount field. */
    val amountError: String? = null,
    val showUpgrade: Boolean = false,
    /** Delete found the item gone already (a sync removed it): the screen says so and closes. */
    val alreadyRemoved: Boolean = false,
) {
    override fun toString(): String =
        "EditorState(fields=${values.keys.sorted()}, error=${error != null}, needsPunycode=$needsPunycode, " +
            "totpError=${totpError != null}, websiteError=${websiteError != null}, amountError=${amountError != null}, " +
            "showUpgrade=$showUpgrade, alreadyRemoved=$alreadyRemoved)"
}

/**
 * Create, edit and delete one record. Records go through core `Normalise.normalForm` and `Wrapper.make` and are
 * committed through the store; deletes write a `SyncMeta` tombstone. Port of `EditorModel` in
 * `ios/App/Editor/EditorModel.swift`. [save] and [delete] read and write the store: call them off the main thread.
 *
 * [existing] null: a new item of [kind]; otherwise the item's own kind wins. [isPro] is read at save time.
 */
class EditorModel(
    private val store: ItemStore,
    existing: VaultItem?,
    kind: EditorKind,
    private val isPro: () -> Boolean,
    private val clock: UnixClock,
    private val random: RandomSource,
) {
    val kind: EditorKind = existing?.let { EditorKind.of(it.kind) } ?: kind
    val isNew: Boolean = existing == null
    private val id: String? = existing?.id

    /** The record as stored, untouched, so an unchanged save writes nothing. */
    private val original: Map<String, JsonValue>? = existing?.record

    private val _state = MutableStateFlow(EditorState(original?.let { values(it, this.kind) } ?: this.kind.defaults()))
    val state: StateFlow<EditorState> = _state.asStateFlow()

    val values: Map<String, String> get() = _state.value.values
    val error: String? get() = _state.value.error
    val needsPunycode: Boolean get() = _state.value.needsPunycode
    val totpError: String? get() = _state.value.totpError
    val websiteError: String? get() = _state.value.websiteError
    val amountError: String? get() = _state.value.amountError
    val showUpgrade: Boolean get() = _state.value.showUpgrade
    val alreadyRemoved: Boolean get() = _state.value.alreadyRemoved

    val titleKey: String get() = if (kind == EditorKind.WEB) "label" else "title"

    /** Free plan: an existing 2FA code stays (and can be cleared); adding or changing one needs Pro. */
    val totpNeedsPro: Boolean get() = kind == EditorKind.WEB && !isPro()

    fun value(key: String): String = _state.value.values[key] ?: ""

    fun set(key: String, v: String) {
        _state.update { s ->
            var n = s.copy(values = s.values + (key to v), error = null)
            if (key == "origin" || key == "url") n = n.copy(needsPunycode = false, websiteError = null)
            if (key == "totp") n = n.copy(totpError = null)
            if (key == "amount_minor" || key == "currency") n = n.copy(amountError = null)
            n
        }
    }

    /** The upgrade sheet (or its stand-in) was shown. */
    fun dismissUpgrade() = _state.update { it.copy(showUpgrade = false) }

    /**
     * A QR code scanned for the 2FA field: a setup code (otpauth link or Base32 secret) fills the field, anything else
     * leaves it as it was and explains why.
     */
    fun scanTotp(code: String) {
        val text = WebsiteInput.trimmed(code)
        val lower = text.lowercase()
        if (lower.startsWith("otpauth-migration:")) return setTotpError(MIGRATION_QR_MESSAGE)
        try {
            if (Totp.parseField(text) == null) return setTotpError(NOT_TOTP_QR_MESSAGE)
            set("totp", text)
        } catch (e: TotpException) {
            setTotpError(if (lower.startsWith("otpauth")) Totp.message(e) else NOT_TOTP_QR_MESSAGE)
        } catch (e: Exception) {
            setTotpError(NOT_TOTP_QR_MESSAGE)
        }
    }

    fun totpCameraUnavailable() = setTotpError(TOTP_CAMERA_MESSAGE)

    private fun setTotpError(message: String) = _state.update { it.copy(totpError = message) }

    // MARK: building the record

    /**
     * The record with [form] applied over the original (unknown fields kept). An empty field the record never had is
     * not added, so opening and saving changes nothing.
     */
    internal fun edited(form: Map<String, String> = values): Map<String, JsonValue> {
        val r = LinkedHashMap(original ?: newRecord(kind, clock.now, random))
        val payload = LinkedHashMap((r["payload"] as? JsonValue.Obj)?.fields ?: emptyMap())
        val scope = LinkedHashMap((r["scope"] as? JsonValue.Obj)?.fields ?: emptyMap())
        for (f in kind.fields) {
            val v = form[f.key] ?: ""
            when {
                // Required for web logins; what was typed is reduced to its origin first.
                kind == EditorKind.WEB && f.key == "origin" -> scope["origin"] = JsonValue.Str(WebsiteInput.origin(v))
                kind == EditorKind.WEB && f.key == "totp" -> {
                    val t = totp(v, r["totp"])
                    if (t == null) r.remove("totp") else r["totp"] = t
                }
                kind == EditorKind.WEB || f.key == "title" -> if (v.isNotEmpty() || r[f.key] != null) r[f.key] = JsonValue.Str(v)
                f.key == "amount_minor" || f.key == "currency" -> Unit // below, together
                f.control == EditorKind.Control.Toggle ->
                    if (v.isNotEmpty() || payload[f.key] != null) payload[f.key] = JsonValue.Bool(v == "true")
                else -> if (v.isNotEmpty() || payload[f.key] != null) payload[f.key] = JsonValue.Str(v)
            }
        }
        if (kind.isPurchaseLike) {
            // Both or neither (the desktop refuses one alone). A saved amount is never dropped, only zeroed.
            val amount = (form["amount_minor"] ?: "").trim(Amount::isSpace)
            val typed = (form["currency"] ?: "").trim(Amount::isSpace).uppercase()
            if (amount.isEmpty() && payload["amount_minor"] == null) {
                payload.remove("amount_minor")
                payload.remove("currency")
            } else {
                val code = typed.ifEmpty { (payload["currency"] as? JsonValue.Str)?.v ?: "XXX" }
                payload["currency"] = JsonValue.Str(code)
                payload["amount_minor"] = JsonValue.Int(Amount.minorUnits(amount, code))
            }
        }
        if (kind == EditorKind.WEB) r["scope"] = JsonValue.Obj(scope) else r["payload"] = JsonValue.Obj(payload)
        return r
    }

    // MARK: actions

    fun save(): SaveResult {
        val form = _state.updateAndGetForm()
        val edited: Map<String, JsonValue> = try {
            edited(form)
        } catch (e: AmountException) {
            return fail(SaveResult.INVALID) { it.copy(amountError = e.message, error = "Check the amount.") }
        } catch (e: TotpException) {
            return fail(SaveResult.INVALID) { it.copy(totpError = Totp.message(e), error = "Check the 2FA secret.") }
        } catch (e: WebsiteInputException) {
            return when (val w = e.error) {
                WebsiteInputError.NeedsPunycode ->
                    fail(SaveResult.NEEDS_PUNYCODE) { it.copy(needsPunycode = true, error = PUNYCODE_MESSAGE) }
                WebsiteInputError.Required ->
                    fail(SaveResult.INVALID) { it.copy(websiteError = WebsiteInput.REQUIRED_MESSAGE, error = "Check the website.") }
                is WebsiteInputError.Invalid ->
                    fail(SaveResult.INVALID) { it.copy(websiteError = w.message, error = "Check the website.") }
            }
        } catch (e: Exception) {
            return fail(SaveResult.INVALID) { it.copy(error = "This item cannot be saved.") }
        }
        // Unchanged: leave the stored bytes alone so the version vector is not bumped.
        val original = original
        if (original != null && same(JsonValue.Obj(edited), JsonValue.Obj(original))) return SaveResult.UNCHANGED
        if (totpNeedsPro && ProFeatures.totpChangeNeedsPro(edited["totp"], original?.get("totp"))) {
            return fail(SaveResult.NEEDS_PRO) {
                it.copy(totpError = ProFeatures.totpMessage, error = "Two-factor codes need Pro.", showUpgrade = true)
            }
        }
        return try {
            val snap = store.load()
            if (isNew && !ItemLimit.allows(ItemLimit.Action.CREATE, snap, isPro())) {
                return fail(SaveResult.NEEDS_PRO) { it.copy(showUpgrade = true) }
            }
            if (original != null) {
                val before = normalOrNull(JsonValue.Obj(original))
                val after = normalOrNull(JsonValue.Obj(edited))
                if (before != null && after != null && same(withoutStamp(before), withoutStamp(after))) return SaveResult.UNCHANGED
            }
            val stamped = LinkedHashMap(edited)
            val now = clock.now
            stamped["updated_at"] = JsonValue.Int(now)
            val created = stamped["created_at"]
            if (created is JsonValue.Int && created.v > now) stamped["created_at"] = JsonValue.Int(now)
            val record = Normalise.normalForm(kind.ns, JsonValue.Obj(stamped))
            val rid = ((record as? JsonValue.Obj)?.fields?.get("id") as? JsonValue.Str)?.v
                ?: return fail(SaveResult.INVALID) { it.copy(error = "This item cannot be saved.") }
            if (id != null && rid != id) return fail(SaveResult.INVALID) { it.copy(error = "This item cannot be saved.") }
            if (isNew && snap.records[rid] != null) return fail(SaveResult.FAILED) { it.copy(error = "This item cannot be saved.") }
            val records = LinkedHashMap(snap.records)
            records[rid] = Wrapper.make(kind.ns, record)
            store.commit(StoreChange(snap.revision, records, snap.meta, snap.sync))
            SaveResult.SAVED
        } catch (e: NormaliseException) {
            when (e.kind) {
                NormaliseException.Kind.NEEDS_PUNYCODE ->
                    fail(SaveResult.NEEDS_PUNYCODE) { it.copy(needsPunycode = true, error = PUNYCODE_MESSAGE) }
                NormaliseException.Kind.REJECTED -> fail(SaveResult.INVALID) { it.copy(error = e.detail) }
                NormaliseException.Kind.NOT_PHONE_KIND -> fail(SaveResult.FAILED) { it.copy(error = SAVE_FAILED_MESSAGE) }
            }
        } catch (e: Exception) {
            fail(SaveResult.FAILED) { it.copy(error = SAVE_FAILED_MESSAGE) }
        }
    }

    /** Clears every message and returns the form as it is now (one consistent read for the whole save). */
    private fun MutableStateFlow<EditorState>.updateAndGetForm(): Map<String, String> {
        update { it.copy(error = null, needsPunycode = false, totpError = null, websiteError = null, amountError = null) }
        return value.values
    }

    private inline fun fail(result: SaveResult, change: (EditorState) -> EditorState): SaveResult {
        _state.update(change)
        return result
    }

    /**
     * Removes the record and writes its tombstone the way `SyncMeta.localView` would (one bump for this device), so
     * the next sync publishes the delete. With no sync state (meta kept after Leave) there is no device to bump with;
     * the meta is left for `SyncMeta.localView`, which tombstones a meta whose record is gone with exactly one bump on
     * the next join. Writing an unbumped tomb here would lose the delete.
     */
    fun delete(): SaveResult {
        val id = id ?: return SaveResult.FAILED
        val r = delete(id, store, clock)
        _state.update {
            it.copy(
                error = if (r == SaveResult.FAILED) "The item could not be deleted on this device." else it.error,
                alreadyRemoved = r == SaveResult.UNCHANGED,
            )
        }
        return r
    }

    fun clearAlreadyRemoved() = _state.update { it.copy(alreadyRemoved = false) }

    private fun normalOrNull(r: JsonValue): JsonValue? = try {
        Normalise.normalForm(kind.ns, r)
    } catch (_: Exception) {
        null
    }

    /** Never shows the form's values or the record. */
    override fun toString(): String = "EditorModel(kind=$kind, isNew=$isNew, state=${_state.value})"

    companion object {
        const val PUNYCODE_MESSAGE = "Enter this website's domain in its xn-- (punycode) form."
        const val ALREADY_REMOVED_MESSAGE = "This item was already removed"
        const val MIGRATION_QR_MESSAGE =
            "This QR code moves accounts out of an authenticator app. Scan the website's own 2FA setup code instead, or import the export on your PC."
        const val NOT_TOTP_QR_MESSAGE = "This QR code is not a 2FA setup code."
        const val TOTP_CAMERA_MESSAGE = "The camera is not available. Paste the setup key instead."
        const val SAVE_FAILED_MESSAGE = "The item could not be saved on this device."

        /** The form's values for a stored record. */
        fun values(r: Map<String, JsonValue>, kind: EditorKind): Map<String, String> {
            val out = LinkedHashMap<String, String>()
            val payload = (r["payload"] as? JsonValue.Obj)?.fields ?: emptyMap()
            for (f in kind.fields) {
                val v: String? = when {
                    kind == EditorKind.WEB && f.key == "origin" -> ((r["scope"] as? JsonValue.Obj)?.fields?.get("origin") as? JsonValue.Str)?.v
                    kind == EditorKind.WEB && f.key == "totp" -> ((r["totp"] as? JsonValue.Obj)?.fields?.get("secret") as? JsonValue.Str)?.v
                    kind == EditorKind.WEB || f.key == "title" -> (r[f.key] as? JsonValue.Str)?.v
                    else -> when (val p = payload[f.key]) {
                        is JsonValue.Bool -> if (p.v) "true" else "false"
                        is JsonValue.Str -> p.v
                        else -> null
                    }
                }
                if (v != null) out[f.key] = v
            }
            if (kind.isPurchaseLike) {
                // The desktop's empty amount is 0 in "XXX" (no currency): shown as blank fields.
                val code = (payload["currency"] as? JsonValue.Str)?.v ?: ""
                val minor = (payload["amount_minor"] as? JsonValue.Int)?.v ?: 0L
                out["currency"] = if (code == "XXX") "" else code
                out["amount_minor"] = if (minor == 0L && (code == "XXX" || code.isEmpty())) "" else Amount.text(minor, code)
            }
            return out
        }

        /**
         * The `totp` value for the 2FA field, in the desktop editor's `config()` shape: {secret, algorithm, digits,
         * period}; a bare secret keeps the stored algorithm/digits/period. An empty field removes it (null); a field
         * showing the stored secret leaves the stored value as it was.
         */
        fun totp(text: String, current: JsonValue?): JsonValue? {
            val existing = (current as? JsonValue.Obj)?.fields
            if (WebsiteInput.trimmed(text).isEmpty()) return if (existing == null) current else null
            if (existing != null && (existing["secret"] as? JsonValue.Str)?.v == text) return current
            var defaults = TotpConfig("")
            if (existing != null) {
                (existing["algorithm"] as? JsonValue.Str)?.let { defaults = defaults.copy(algorithm = it.v) }
                (existing["digits"] as? JsonValue.Int)?.let { defaults = defaults.copy(digits = it.v.toInt()) }
                (existing["period"] as? JsonValue.Int)?.let { defaults = defaults.copy(period = it.v.toInt()) }
            }
            val c = Totp.parseField(text, defaults) ?: return null
            return JsonValue.Obj(
                mapOf(
                    "secret" to JsonValue.Str(c.secret), "algorithm" to JsonValue.Str(c.algorithm),
                    "digits" to JsonValue.Int(c.digits.toLong()), "period" to JsonValue.Int(c.period.toLong()),
                ),
            )
        }

        /** An empty record of [kind]. */
        fun newRecord(kind: EditorKind, now: Long, random: RandomSource): Map<String, JsonValue> {
            val n = JsonValue.Int(now)
            val r = linkedMapOf(
                "id" to JsonValue.Str(uuid4(random)), "kind" to JsonValue.Str(kind.raw),
                "created_at" to n, "updated_at" to n, "favorite" to JsonValue.Bool(false), "tags" to JsonValue.Arr(emptyList()),
            )
            if (kind == EditorKind.WEB) {
                r["label"] = JsonValue.Str("")
                r["username"] = JsonValue.Str("")
                r["password"] = JsonValue.Str("")
                r["scope"] = JsonValue.Obj(emptyMap())
            } else {
                r["title"] = JsonValue.Str("")
                r["payload"] = JsonValue.Obj(emptyMap())
            }
            return r
        }

        /** Python `str(uuid.uuid4())`. */
        fun uuid4(random: RandomSource): String {
            val b = random.bytes(16)
            b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()
            b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()
            val h = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
            return listOf(0 until 8, 8 until 12, 12 until 16, 16 until 20, 20 until 32).joinToString("-") { h.substring(it) }
        }

        /** Byte comparison of canonical forms. */
        fun same(a: JsonValue, b: JsonValue): Boolean = try {
            CanonicalJson.encode(a, Dialect.UTF8).contentEquals(CanonicalJson.encode(b, Dialect.UTF8))
        } catch (_: Exception) {
            false
        }

        private fun withoutStamp(r: JsonValue): JsonValue = (r as? JsonValue.Obj)?.let { JsonValue.Obj(it.fields - "updated_at") } ?: r

        /** [EditorModel.delete] for any item id (the passkey screen and delete-only kinds share it). */
        fun delete(id: String, store: ItemStore, clock: UnixClock): SaveResult = try {
            val snap = store.load()
            if (id !in snap.records) {
                SaveResult.UNCHANGED
            } else {
                val records = LinkedHashMap(snap.records).apply { remove(id) }
                val meta = LinkedHashMap(snap.meta)
                val m = meta[id]
                val device = snap.sync?.deviceId
                if (m != null && !m.deleted && device != null) {
                    meta[id] = SyncMeta.tomb(VersionVector.bump(m.vv, device), clock.now)
                }
                store.commit(StoreChange(snap.revision, records, meta, snap.sync))
                SaveResult.SAVED
            }
        } catch (_: Exception) {
            SaveResult.FAILED
        }
    }
}

/** The editor screen's copy (the iPhone's, with "phone" for "iPhone"). */
object EditorScreenText {
    fun title(kind: EditorKind, isNew: Boolean): String = (if (isNew) "New " else "Edit ") + kind.label.lowercase()

    const val DELETE_ITEM = "Delete item"
    const val DELETE_TITLE = "Delete this item?"
    const val DELETE_MESSAGE = "It is removed from this phone and from your other devices at the next sync."

    /** The detail screen's Delete, for kinds the phone cannot edit. */
    const val DELETE_ONLY_MESSAGE = "It is removed from this phone and from your other devices at the next sync. It can only be edited on your PC."
    const val DELETE_FAILED = "The item could not be deleted on this device."
    const val URL_PUNYCODE =
        "This address has non-ASCII letters. Type the domain in its xn-- form, for example https://xn--bcher-kva.example."
    const val ORIGIN_PUNYCODE =
        "This address has non-ASCII letters. Type the domain as it appears in its xn-- form, for example https://xn--bcher-kva.example."
    const val SECRET_EMPTY = "Empty. Tap the eye to paste or type it."

    /** A hidden multi-line secret: "•••••••• (3 lines)". */
    fun hiddenLines(text: String): String = "•••••••• (${text.split('\n', '\r').count { it.isNotEmpty() }} lines)"
}

/** The editor's date fields: ISO `yyyy-MM-dd` in UTC, as the desktop stores them. */
object IsoDate {
    private val format: java.time.format.DateTimeFormatter =
        java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd", java.util.Locale.ROOT)
            .withResolverStyle(java.time.format.ResolverStyle.STRICT)

    /** The day [text] names when it is exactly a valid `yyyy-MM-dd`; null for anything else (an ISO week date, say). */
    fun parse(text: String): java.time.LocalDate? = try {
        java.time.LocalDate.parse(text, format).takeIf { it.format(format) == text }
    } catch (_: Exception) {
        null
    }

    fun format(day: java.time.LocalDate): String = day.format(format)

    /** Today in UTC ("Add"). */
    fun today(clock: UnixClock): String = format(java.time.LocalDate.ofEpochDay(Math.floorDiv(clock.now, 86_400L)))

    /** UTC midnight in milliseconds (the date picker's unit). */
    fun utcMillis(day: java.time.LocalDate): Long = day.toEpochDay() * 86_400_000L

    fun fromUtcMillis(millis: Long): String = format(java.time.LocalDate.ofEpochDay(Math.floorDiv(millis, 86_400_000L)))
}
