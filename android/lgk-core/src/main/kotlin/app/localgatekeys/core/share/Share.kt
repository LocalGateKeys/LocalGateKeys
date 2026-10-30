package app.localgatekeys.core.share

import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.crypto.Bip39
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.CryptoBoxException
import app.localgatekeys.core.primitives.RandomSource
import java.util.Locale

/**
 * A package cannot be made or opened. [reason] is one of the spec's codes: `bad-code`, `malformed`, `unsupported`,
 * `already-opened`, `wrong-code`, `expired`, `not-shareable`, `too-large`. The message never holds item content.
 */
/**
 * A refused share. [reason] is the stable class of failure the callers branch on; [code] names the exact case (so screens can
 * show their own text); [message] is English for logs and tests.
 */
class ShareException(val reason: String, message: String, val code: String = reason) : Exception(message)

/** The clear part of a package, readable before the code is typed. */
class ShareHeader internal constructor(val id: String, val sender: String, internal val envelope: Map<String, JsonValue>) {
    override fun toString(): String = "ShareHeader(id=$id)"
}

/** One opened package. [item] is the shared record (secrets inside: never log it). */
class OpenedShare(val id: String, val sender: String, val createdAt: Long, val expiresAt: Long, val item: JsonValue.Obj) {
    override fun toString(): String = "OpenedShare(id=$id)"
}

/**
 * Secure local sharing, `.lgkshare` v1 (`docs/formats/LGKSHARE_V1.md`; Python `src/localvault/share.py`): one item
 * under a 6-word one-time code. Format core only: seal, read the clear header, open. Vectors: `tests/vectors/share`.
 */
object Share {
    const val FORMAT = "localgatekeys-share"
    const val VERSION = 1L
    const val CODE_WORDS = 6
    const val LIFETIME = 24L * 3600
    const val CLOCK_SKEW = 300L
    const val MAX_PACKAGE = 256 * 1024
    const val QR_LIMIT = 2048
    const val SENDER_LIMIT = 64
    const val CODE_QR_PREFIX = "lgkshare-code:"
    const val FILE_EXTENSION = "lgkshare"
    const val TIME_COST = 2L
    const val MEMORY_KIB = 19456L
    const val PARALLELISM = 1L
    private const val DEFAULT_SENDER = "A LocalGateKeys device"

    /** Never travel: attachments and passkeys. */
    val FORBIDDEN_FIELDS = listOf("attachments", "attachment_ids", "passkeys", "passkey")
    /** Local-only keys removed before sealing. */
    val LOCAL_ONLY = listOf("policy", "password_history", "collection_ids", "favorite", "usage", "last_used_at")

    private val HEADER_KEYS = setOf("format", "version", "id", "sender", "kdf", "nonce", "ciphertext")
    private val PAYLOAD_KEYS = setOf("version", "created_at", "expires_at", "item")
    private val KDF_KEYS = setOf("name", "time_cost", "memory_cost_kib", "parallelism", "salt")
    private val SPLIT = Regex("(?U)[\\s·.,\\-]+")
    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    private const val NOT_A_SHARE = "This is not a shared LocalGateKeys item."
    private const val DAMAGED = "The shared item is damaged."

    private val allowed: Set<String> by lazy { Bip39.words.toHashSet() }

    /** Six words from the BIP39 English list (66 bits), shown on the sender's screen only. */
    fun generateCode(random: RandomSource): String {
        val words = Bip39.words
        return (0 until CODE_WORDS).joinToString(" ") { words[uniform(random, words.size)] }
    }

    private fun uniform(random: RandomSource, bound: Int): Int {
        // 2048 is a power of two: the low 11 bits of two random bytes are uniform.
        require(bound > 0 && bound and (bound - 1) == 0)
        val b = random.bytes(2)
        return (((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)) and (bound - 1)
    }

    /** Lower case, split on spaces, `·`, `.`, `,` or `-`: exactly six list words joined with one space. */
    fun normalizeCode(text: String): String {
        if (text.length > 512) throw ShareException("bad-code", "Enter the six words of the code.", "need-six-words")
        val tokens = text.trim().lowercase(Locale.ROOT).split(SPLIT).filter { it.isNotEmpty() }
        if (tokens.size != CODE_WORDS || tokens.any { it !in allowed }) throw ShareException("bad-code", "Enter the six words of the code.", "need-six-words")
        return tokens.joinToString(" ")
    }

    private fun key(code: String, salt: ByteArray): ByteArray {
        val password = normalizeCode(code).toByteArray(Charsets.UTF_8)
        try {
            return Argon2.default.derive(password, salt, MEMORY_KIB.toInt(), TIME_COST.toInt(), PARALLELISM.toInt(), 32)
        } finally {
            password.fill(0)
        }
    }

    private fun truthy(v: JsonValue?): Boolean = when (v) {
        null, JsonValue.Null -> false
        is JsonValue.Bool -> v.v
        is JsonValue.Int -> v.v != 0L
        is JsonValue.Float -> v.v != 0.0
        is JsonValue.Str -> v.v.isNotEmpty()
        is JsonValue.Arr -> v.items.isNotEmpty()
        is JsonValue.Obj -> v.fields.isNotEmpty()
    }

    /** Python `_clean_item`: a kind, no passkey or attachments, local-only and forbidden keys removed. */
    fun cleanItem(item: JsonValue): JsonValue.Obj {
        val obj = item as? JsonValue.Obj ?: throw ShareException("malformed", "Only a saved item can be shared.", "not-saved")
        val kind = (obj.fields["kind"] as? JsonValue.Str)?.v
        if (kind.isNullOrEmpty()) throw ShareException("malformed", "Only a saved item can be shared.", "not-saved")
        if (kind == "passkey" || FORBIDDEN_FIELDS.any { truthy(obj.fields[it]) }) {
            throw ShareException("not-shareable", "Passkeys and attachments cannot be shared.", "passkeys-attachments")
        }
        return JsonValue.Obj(obj.fields.filterKeys { it !in LOCAL_ONLY && it !in FORBIDDEN_FIELDS })
    }

    /** True when the item can be shared at all (for showing the Share action). */
    fun isShareable(item: JsonValue): Boolean = try {
        cleanItem(item); true
    } catch (e: ShareException) {
        false
    }

    private fun canonical(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    private fun aad(header: Map<String, JsonValue>): ByteArray =
        canonical(JsonValue.Obj(header.filterKeys { it in setOf("format", "version", "id", "sender", "kdf", "nonce") }))

    private fun kdf(salt: ByteArray): JsonValue.Obj = JsonValue.Obj(
        mapOf(
            "name" to JsonValue.Str("argon2id"),
            "time_cost" to JsonValue.Int(TIME_COST),
            "memory_cost_kib" to JsonValue.Int(MEMORY_KIB),
            "parallelism" to JsonValue.Int(PARALLELISM),
            "salt" to JsonValue.Str(Base64Std.encode(salt)),
        ),
    )

    private fun truncateCodePoints(s: String, max: Int): String {
        if (s.codePointCount(0, s.length) <= max) return s
        return s.substring(0, s.offsetByCodePoints(0, max))
    }

    /** Python `str.strip()` on the ends: whitespace as Python sees it. */
    private fun pyStrip(s: String): String = s.trim { Character.isWhitespace(it) || Character.isSpaceChar(it) }

    private fun randomUuid(random: RandomSource): String {
        val b = random.bytes(16)
        b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()
        b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()
        val h = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
    }

    /**
     * The `.lgkshare` bytes for one item. [packageId], [salt] and [nonce] are for vectors only; otherwise they come
     * from [random].
     */
    fun seal(
        item: JsonValue,
        code: String,
        sender: String,
        now: Long,
        random: RandomSource,
        packageId: String? = null,
        salt: ByteArray? = null,
        nonce: ByteArray? = null,
    ): ByteArray {
        val name = truncateCodePoints(pyStrip(sender), SENDER_LIMIT).ifEmpty { DEFAULT_SENDER }
        val s = salt ?: random.bytes(16)
        val n = nonce ?: random.bytes(12)
        val header = linkedMapOf<String, JsonValue>(
            "format" to JsonValue.Str(FORMAT),
            "version" to JsonValue.Int(VERSION),
            "id" to JsonValue.Str(packageId ?: randomUuid(random)),
            "sender" to JsonValue.Str(name),
            "kdf" to kdf(s),
            "nonce" to JsonValue.Str(Base64Std.encode(n)),
        )
        val payload = JsonValue.Obj(
            mapOf(
                "version" to JsonValue.Int(VERSION),
                "created_at" to JsonValue.Int(now),
                "expires_at" to JsonValue.Int(now + LIFETIME),
                "item" to cleanItem(item),
            ),
        )
        val k = key(code, s)
        val plain = canonical(payload)
        val ciphertext = try {
            CryptoBox.sealGcm(k, n, plain, aad(header))
        } finally {
            k.fill(0); plain.fill(0)
        }
        val data = canonical(JsonValue.Obj(header + ("ciphertext" to JsonValue.Str(Base64Std.encode(ciphertext)))))
        if (data.size > MAX_PACKAGE) throw ShareException("too-large", "This item is too large to share.")
        return data
    }

    private fun b64(v: JsonValue?, size: Int? = null): ByteArray {
        val s = (v as? JsonValue.Str)?.v ?: throw ShareException("malformed", DAMAGED, "damaged")
        val out = try {
            Base64Std.decodeStrict(s)
        } catch (e: Exception) {
            throw ShareException("malformed", DAMAGED, "damaged")
        }
        if (size != null && out.size != size) throw ShareException("malformed", DAMAGED, "damaged")
        return out
    }

    private fun isInt(v: JsonValue?, value: Long): Boolean = v is JsonValue.Int && v.v == value

    /** The clear part, for the pop-up before the code is typed: id and sender. */
    fun readHeader(data: ByteArray): ShareHeader {
        if (data.size > MAX_PACKAGE) throw ShareException("malformed", NOT_A_SHARE, "not-a-share")
        val envelope = try {
            CanonicalJson.parse(data)
        } catch (e: Exception) {
            throw ShareException("malformed", NOT_A_SHARE, "not-a-share")
        }
        val fields = (envelope as? JsonValue.Obj)?.fields ?: throw ShareException("malformed", NOT_A_SHARE, "not-a-share")
        if ((fields["format"] as? JsonValue.Str)?.v != FORMAT) throw ShareException("malformed", NOT_A_SHARE, "not-a-share")
        if (!isInt(fields["version"], VERSION)) {
            throw ShareException("unsupported", "This item was shared by a newer LocalGateKeys. Update the app.")
        }
        if (fields.keys != HEADER_KEYS) throw ShareException("malformed", DAMAGED, "damaged")
        val kdf = (fields["kdf"] as? JsonValue.Obj)?.fields ?: throw ShareException("malformed", DAMAGED, "damaged")
        if (kdf.keys != KDF_KEYS || (kdf["name"] as? JsonValue.Str)?.v != "argon2id" || !isInt(kdf["time_cost"], TIME_COST) ||
            !isInt(kdf["memory_cost_kib"], MEMORY_KIB) || !isInt(kdf["parallelism"], PARALLELISM)
        ) {
            throw ShareException("malformed", DAMAGED, "damaged")
        }
        val id = (fields["id"] as? JsonValue.Str)?.v ?: throw ShareException("malformed", DAMAGED, "damaged")
        if (!UUID_RE.matches(id)) throw ShareException("malformed", DAMAGED, "damaged")
        val sender = (fields["sender"] as? JsonValue.Str)?.v ?: throw ShareException("malformed", DAMAGED, "damaged")
        if (sender.codePointCount(0, sender.length) > SENDER_LIMIT) throw ShareException("malformed", DAMAGED, "damaged")
        b64(kdf["salt"], 16)
        b64(fields["nonce"], 12)
        return ShareHeader(id, sender, fields)
    }

    /** Decrypts and checks one package. [opened]: the package ids this device already opened. */
    fun open(data: ByteArray, code: String, now: Long, opened: Set<String> = emptySet()): OpenedShare =
        open(readHeader(data), code, now, opened)

    fun open(header: ShareHeader, code: String, now: Long, opened: Set<String> = emptySet()): OpenedShare {
        val envelope = header.envelope
        if (header.id in opened) throw ShareException("already-opened", "This shared item was already opened on this device.")
        val salt = b64((envelope["kdf"] as JsonValue.Obj).fields["salt"], 16)
        val k = key(code, salt)
        val plain = try {
            CryptoBox.openGcm(k, b64(envelope["nonce"], 12), b64(envelope["ciphertext"]), aad(envelope))
        } catch (e: CryptoBoxException) {
            throw ShareException("wrong-code", "That code does not open this item. Check the six words.")
        } finally {
            k.fill(0)
        }
        val payload = try {
            CanonicalJson.parse(plain)
        } catch (e: Exception) {
            throw ShareException("malformed", DAMAGED, "damaged")
        } finally {
            plain.fill(0)
        }
        val p = (payload as? JsonValue.Obj)?.fields ?: throw ShareException("malformed", DAMAGED, "damaged")
        if (!isInt(p["version"], VERSION) || p.keys != PAYLOAD_KEYS) throw ShareException("malformed", DAMAGED, "damaged")
        val created = (p["created_at"] as? JsonValue.Int)?.v ?: throw ShareException("malformed", DAMAGED, "damaged")
        val expires = (p["expires_at"] as? JsonValue.Int)?.v ?: throw ShareException("malformed", DAMAGED, "damaged")
        if (expires != created + LIFETIME) throw ShareException("malformed", DAMAGED, "damaged")
        if (created > now + CLOCK_SKEW) {
            throw ShareException("malformed", "The shared item has a date in the future. Check this device's clock.", "future-date")
        }
        if (now >= expires) throw ShareException("expired", "This shared item expired. Ask for it to be shared again.")
        val raw = p["item"] as? JsonValue.Obj ?: throw ShareException("not-shareable", "This shared item holds content that cannot be shared.", "content-not-shareable")
        val item = cleanItem(raw) // Python: a missing kind is malformed, a passkey or attachment not-shareable
        if (item != raw) throw ShareException("not-shareable", "This shared item holds content that cannot be shared.", "content-not-shareable")
        return OpenedShare(header.id, header.sender, created, expires, item)
    }

    private fun originOf(url: String): String {
        val u = try {
            java.net.URI(url)
        } catch (e: Exception) {
            return url
        }
        val scheme = u.scheme ?: return url
        val authority = u.rawAuthority ?: return url
        return scheme.lowercase(Locale.ROOT) + "://" + authority.lowercase(Locale.ROOT)
    }

    /**
     * Python `share.stored_form`: the item in the stored shape the spec defines (`scope` for logins, `payload` for
     * typed items). Every sender seals the stored record; packages from early builds may carry the display shape
     * (a login's top-level `urls`, a typed item's `fields`), which is converted here before the normal form.
     */
    fun storedForm(item: JsonValue.Obj): JsonValue.Obj {
        val rec = LinkedHashMap(item.fields)
        val kind = (rec["kind"] as? JsonValue.Str)?.v
        if (kind == "web" || kind == "desktop") {
            if ("label" !in rec && rec["title"] is JsonValue.Str) rec["label"] = rec.getValue("title")
            rec.remove("title")
            val urls = rec.remove("urls")
            if (rec["scope"] !is JsonValue.Obj && kind == "web") {
                val rows = (urls as? JsonValue.Arr)?.items.orEmpty()
                    .filterIsInstance<JsonValue.Obj>().filter { it.fields["url"] is JsonValue.Str }
                val scope = linkedMapOf<String, JsonValue>("origin" to JsonValue.Str(""))
                rows.firstOrNull()?.let { first ->
                    val u = (first.fields.getValue("url") as JsonValue.Str).v
                    val exact = (first.fields["match"] as? JsonValue.Str)?.v == "exact_origin"
                    scope["origin"] = JsonValue.Str(if (exact) u else originOf(u))
                    scope["urls"] = JsonValue.Arr(rows)
                }
                rec["scope"] = JsonValue.Obj(scope)
            }
        } else {
            if ("title" !in rec && rec["label"] is JsonValue.Str) rec["title"] = rec.getValue("label")
            rec.remove("label")
            val fields = rec.remove("fields")
            if (rec["payload"] !is JsonValue.Obj) rec["payload"] = fields as? JsonValue.Obj ?: JsonValue.Obj(emptyMap())
        }
        return JsonValue.Obj(rec)
    }

    /** Small packages may travel as one QR code; larger ones go as a file. */
    fun fitsQr(data: ByteArray): Boolean = data.size <= QR_LIMIT

    /** The second QR (the key), when the code is not read out. */
    fun codeQrText(code: String): String = CODE_QR_PREFIX + normalizeCode(code).replace(" ", "-")

    fun codeFromQrText(text: String): String {
        if (!text.startsWith(CODE_QR_PREFIX)) throw ShareException("bad-code", "This QR code is not a LocalGateKeys share code.", "not-a-share-qr")
        return normalizeCode(text.substring(CODE_QR_PREFIX.length))
    }

    /** True when [text] looks like a package (a scanned QR), before any parsing. */
    fun looksLikePackage(text: String): Boolean = text.startsWith("{") && text.contains("\"$FORMAT\"")
}
