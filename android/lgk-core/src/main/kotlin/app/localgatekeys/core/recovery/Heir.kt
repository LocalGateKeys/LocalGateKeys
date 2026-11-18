package app.localgatekeys.core.recovery

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.X25519
import app.localgatekeys.core.records.PyStrip
import java.security.MessageDigest
import java.text.Normalizer

/**
 * `reason`: `invalid`, `malformed`, `conflict` (a synced plan that re-keys the stored one), `unsupported`,
 * `bad-signature`, `need-more` ([missing] shards short), `duplicate`, `mixed-plans` or `check-failed`
 * (desktop `heir.HeirError`).
 */
class HeirException(val reason: String, message: String = reason, val missing: Int = 0) : Exception(message)

/** One verified `.lgkheir` package: the shard ([share] = `[index, 32 bytes]`) and the plan facts it carries. */
class Shard(
    val packageId: String,
    val planId: String,
    val index: Int,
    val holder: String,
    val k: Int,
    val n: Int,
    val waitDays: Int,
    val created: Long,
    val owner: String,
    signer: ByteArray,
    share: ByteArray,
    checkSalt: ByteArray,
    check: ByteArray,
) {
    private val signerBytes = signer.copyOf()
    private val shareBytes = share.copyOf()
    private val saltBytes = checkSalt.copyOf()
    private val checkBytes = check.copyOf()
    val signer: ByteArray get() = signerBytes.copyOf()
    val share: ByteArray get() = shareBytes.copyOf()
    val checkSalt: ByteArray get() = saltBytes.copyOf()
    val check: ByteArray get() = checkBytes.copyOf()

    internal fun sameplan(other: Shard): Boolean =
        planId == other.planId && signerBytes.contentEquals(other.signerBytes) && k == other.k && n == other.n &&
            waitDays == other.waitDays && created == other.created && owner == other.owner &&
            saltBytes.contentEquals(other.saltBytes) && checkBytes.contentEquals(other.checkBytes)

    /** Wipes this shard's copy of the share (best effort). */
    fun wipe() = shareBytes.fill(0)

    override fun toString(): String = "Shard(plan=$planId, index=$index)" // never the share
}

/**
 * The owner's plan as one of the owner's phones holds it: the synced record (desktop `heir.synced_record`), received
 * from the owner's computer. It carries the plan's Ed25519 signing key, so this phone can sign deny and grant files.
 */
class HeirPlan internal constructor(
    val planId: String,
    val k: Int,
    val n: Int,
    val holders: List<String>,
    val waitDays: Int,
    val created: Long,
    val owner: String,
    signer: ByteArray,
    signingSeed: ByteArray,
    checkSalt: ByteArray,
    check: ByteArray,
    backupPublic: ByteArray,
    holderKeys: List<ByteArray>,
    val stale: Boolean,
    val denied: List<String>,
) {
    private val signerBytes = signer.copyOf()
    private val seedBytes = signingSeed.copyOf()
    private val saltBytes = checkSalt.copyOf()
    private val checkBytes = check.copyOf()
    private val backupBytes = backupPublic.copyOf()
    private val holderKeyBytes = holderKeys.map { it.copyOf() }
    val signer: ByteArray get() = signerBytes.copyOf()
    val checkSalt: ByteArray get() = saltBytes.copyOf()
    val check: ByteArray get() = checkBytes.copyOf()
    val backupPublic: ByteArray get() = backupBytes.copyOf()

    /** A copy of the plan's Ed25519 seed (the caller zeroes it). */
    fun signingSeed(): ByteArray = seedBytes.copyOf()

    /** A copy of holder [index]'s proof key (1-based). */
    fun holderKey(index: Int): ByteArray = holderKeyBytes[index - 1].copyOf()

    override fun toString(): String = "HeirPlan(plan=$planId, k=$k, n=$n)" // never key material
}

/**
 * Emergency access shards and the owner's plan record: port of `src/localvault/heir.py` (byte rules in
 * `docs/formats/LGKHEIR_V1.md`, vectors in `tests/vectors/heir`). Phones read and combine shards, check the entropy,
 * hold the plan by sync and merge it like the desktop; they never make a plan (the plan protects the computer's vault).
 */
object Heir {
    const val FORMAT = "localgatekeys-heir"
    const val VERSION = 1L
    const val KIND = "heir-shard"
    const val MAX_PACKAGE = 4096
    const val QR_PREFIX = "lgkheir:"
    const val QR_LIMIT = 2048
    const val NICKNAME_LIMIT = 32
    const val OWNER_LIMIT = Envelope.SENDER_LIMIT
    const val MIN_WAIT_DAYS = 1
    const val MAX_WAIT_DAYS = 30
    const val DENIED_LIMIT = 64
    /** Sync namespace and the one state id of the owner's plan (desktop `vault_bridge.HEIR_NS` / `HEIR_STATE_ID`). */
    const val NS = "heir"
    const val STATE_ID = "heir:plan"
    val CHECK_INFO: ByteArray = "LocalGateKeys heir check v1\n".toByteArray(Charsets.US_ASCII)
    val HOLDER_INFO: ByteArray = "LocalGateKeys heir holder v1\n".toByteArray(Charsets.US_ASCII)
    val BACKUP_KEY_INFO: ByteArray = "LocalGateKeys heir backup key v1\n".toByteArray(Charsets.US_ASCII)

    private val PAYLOAD_KEYS = setOf("kind", "plan_id", "index", "holder", "k", "n", "wait_days", "created", "share", "check_salt", "check")
    private val RECORD_KEYS = setOf(
        "version", "plan_id", "k", "n", "holders", "wait_days", "folder", "created", "owner", "signer",
        "signing_key", "check_salt", "check", "backup_public", "holder_keys",
    )
    /** Never synced: the shared folder's path on that device, and whether it made the plan. */
    private val LOCAL_ONLY_KEYS = setOf("folder", "home")
    /** Exactly the keys of a synced record (desktop `_SYNCED_KEYS`). */
    val SYNCED_KEYS: Set<String> = (RECORD_KEYS - "folder") + setOf("stale", "denied")
    private val MUTABLE_KEYS = setOf("stale", "denied")

    // ---- validation -----------------------------------------------------------------------

    private fun bad(): Nothing = throw HeirException("malformed")

    /** Desktop `_printable`: NFC, Python-stripped, 1..[limit] code points with no control, format, surrogate or private-use ones (see [isOther]). */
    fun printable(raw: String, limit: Int, allowEmpty: Boolean = false): String {
        val name = PyStrip.strip(Normalizer.normalize(raw, Normalizer.Form.NFC))
        val count = Envelope.length(name)
        if ((count == 0 && !allowEmpty) || count > limit || name.codePoints().anyMatch { isOther(it) }) {
            throw HeirException("invalid", "A name must be 1 to $limit printable characters")
        }
        return name
    }

    /**
     * Unicode general categories Cc, Cf, Cs and Co. Unassigned (Cn) is accepted on purpose: these names come from
     * signed packages the desktop already checked against its own (often newer) Unicode tables, and an older phone's
     * JDK or ICU reports later emoji (Unicode 14/15) as unassigned, which would refuse a valid shard as `malformed`.
     */
    internal fun isOther(cp: Int): Boolean = when (Character.getType(cp)) {
        Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.SURROGATE.toInt(),
        Character.PRIVATE_USE.toInt() -> true
        else -> false
    }

    private fun isInt(v: JsonValue?): Boolean = v is JsonValue.Int

    private fun int(v: JsonValue?): Long = (v as? JsonValue.Int)?.v ?: throw HeirException("invalid")

    private fun checkCounts(k: JsonValue?, n: JsonValue?, waitDays: JsonValue?) {
        val kk = int(k)
        val nn = int(n)
        if (!(Sss.MIN_K <= kk && kk <= nn && nn <= Sss.MAX_N)) throw HeirException("invalid")
        val w = int(waitDays)
        if (w < MIN_WAIT_DAYS || w > MAX_WAIT_DAYS) throw HeirException("invalid")
    }

    private fun holders(value: JsonValue?, n: Long): List<String> {
        val list = (value as? JsonValue.Arr)?.items ?: throw HeirException("invalid")
        val names = list.map { printable((it as? JsonValue.Str)?.v ?: throw HeirException("invalid"), NICKNAME_LIMIT) }
        if (names.size.toLong() != n) throw HeirException("invalid")
        if (names.map { Casefold.fold(it) }.toSet().size != names.size) throw HeirException("invalid")
        return names
    }

    // ---- derived keys ---------------------------------------------------------------------

    private fun info(prefix: ByteArray, planId: String) = prefix + planId.toByteArray(Charsets.US_ASCII)

    /** `HKDF-SHA256(ikm=entropy, salt, info=CHECK_INFO || plan_id)`, 32 bytes. */
    fun entropyCheck(entropy: ByteArray, planId: String, salt: ByteArray): ByteArray {
        if (entropy.size != Sss.SECRET_LEN || salt.size != 16) throw HeirException("invalid")
        return CryptoBox.hkdf(entropy, salt, info(CHECK_INFO, planId), 32)
    }

    /** A holder's proof key: `HKDF-SHA256(ikm=share (33 bytes), salt, info=HOLDER_INFO || plan_id)`. */
    fun holderKey(share: ByteArray, planId: String, salt: ByteArray): ByteArray {
        if (share.size != Sss.SHARE_LEN || salt.size != 16) throw HeirException("invalid")
        return CryptoBox.hkdf(share, salt, info(HOLDER_INFO, planId), 32)
    }

    /** The clamped X25519 key the heir folder's backups are locked to (the caller zeroes it). */
    fun backupPrivateKey(entropy: ByteArray, planId: String, salt: ByteArray): ByteArray {
        if (entropy.size != Sss.SECRET_LEN || salt.size != 16) throw HeirException("invalid")
        val key = CryptoBox.hkdf(entropy, salt, info(BACKUP_KEY_INFO, planId), 32)
        key[0] = (key[0].toInt() and 0xF8).toByte()
        key[31] = ((key[31].toInt() and 0x7F) or 0x40).toByte()
        return key
    }

    fun backupPublicKey(entropy: ByteArray, planId: String, salt: ByteArray): ByteArray {
        val private = backupPrivateKey(entropy, planId, salt)
        try {
            return X25519.publicKey(private)
        } finally {
            private.fill(0)
        }
    }

    /** Whether [entropy] is the one the plan was made from (constant-time compare of the HKDF check). */
    fun verifyEntropy(planId: String, salt: ByteArray, check: ByteArray, entropy: ByteArray): Boolean {
        if (entropy.size != Sss.SECRET_LEN) return false
        val mine = entropyCheck(entropy, planId, salt)
        try {
            return MessageDigest.isEqual(mine, check)
        } finally {
            mine.fill(0)
        }
    }

    fun verifyEntropy(shard: Shard, entropy: ByteArray) = verifyEntropy(shard.planId, shard.checkSalt, shard.check, entropy)

    fun verifyEntropy(plan: HeirPlan, entropy: ByteArray) = verifyEntropy(plan.planId, plan.checkSalt, plan.check, entropy)

    // ---- packages -------------------------------------------------------------------------

    /** The signed package of one shard, as the desktop's `create_plan` writes it. */
    fun sealPackage(
        planId: String, share: ByteArray, holder: String, k: Int, n: Int, waitDays: Int, created: Long,
        checkSalt: ByteArray, check: ByteArray, owner: String, packageId: String, signingSeed: ByteArray,
    ): ByteArray {
        val payload = linkedMapOf<String, JsonValue>(
            "kind" to JsonValue.Str(KIND),
            "plan_id" to JsonValue.Str(planId),
            "index" to JsonValue.Int((share[0].toInt() and 0xFF).toLong()),
            "holder" to JsonValue.Str(holder),
            "k" to JsonValue.Int(k.toLong()),
            "n" to JsonValue.Int(n.toLong()),
            "wait_days" to JsonValue.Int(waitDays.toLong()),
            "created" to JsonValue.Int(created),
            "share" to JsonValue.Str(Envelope.b64e(share)),
            "check_salt" to JsonValue.Str(Envelope.b64e(checkSalt)),
            "check" to JsonValue.Str(Envelope.b64e(check)),
        )
        return Envelope.seal(FORMAT, VERSION, packageId, owner, payload, signingSeed)
    }

    /** Parses and verifies one `.lgkheir` package (signature first, then every payload rule). */
    fun readPackage(data: ByteArray): Shard {
        val opened = try {
            Envelope.open(data, FORMAT, VERSION, MAX_PACKAGE)
        } catch (e: EnvelopeException) {
            throw HeirException(e.reason, "This is not a valid emergency access shard")
        }
        val p = opened.payload
        try {
            if (p.keys != PAYLOAD_KEYS || p["kind"] != JsonValue.Str(KIND)) bad()
            checkCounts(p["k"], p["n"], p["wait_days"])
            val index = int(p["index"])
            val n = int(p["n"])
            val created = int(p["created"])
            val holder = (p["holder"] as? JsonValue.Str)?.v ?: bad()
            if (index < 1 || index > n || created < 0 || printable(holder, NICKNAME_LIMIT) != holder ||
                printable(opened.sender, OWNER_LIMIT, allowEmpty = true) != opened.sender
            ) bad()
            val share = Envelope.b64d(p["share"], Sss.SHARE_LEN)
            if ((share[0].toInt() and 0xFF).toLong() != index) bad()
            return Shard(
                opened.id, Envelope.checkedId(p["plan_id"]), index.toInt(), holder, int(p["k"]).toInt(), n.toInt(),
                int(p["wait_days"]).toInt(), created, opened.sender, opened.signer, share,
                Envelope.b64d(p["check_salt"], 16), Envelope.b64d(p["check"], 32),
            )
        } catch (e: EnvelopeException) {
            throw HeirException("malformed", "This emergency access shard is damaged")
        } catch (e: HeirException) {
            throw HeirException("malformed", "This emergency access shard is damaged")
        }
    }

    /** Packages that must belong to one plan, each shard once (at least one). */
    fun checkShards(packages: List<ByteArray>): List<Shard> {
        val shards = packages.map { readPackage(it) }
        if (shards.isEmpty()) throw HeirException("need-more", "Add the shards you were given", missing = Sss.MIN_K)
        if (shards.any { !it.sameplan(shards[0]) }) throw HeirException("mixed-plans", "These shards come from different plans")
        if (shards.map { it.index }.toSet().size != shards.size) throw HeirException("duplicate", "The same shard was added twice")
        return shards
    }

    /** The recovery entropy from at least `k` packages of one plan, confirmed against the plan's check. */
    fun combinePackages(packages: List<ByteArray>): ByteArray {
        val shards = checkShards(packages)
        val k = shards[0].k
        if (shards.size < k) throw HeirException("need-more", "${k - shards.size} more shard(s) needed", missing = k - shards.size)
        val parts = shards.map { it.share }
        val entropy = try {
            Sss.combine(parts)
        } finally {
            parts.forEach { it.fill(0) }
        }
        if (!verifyEntropy(shards[0], entropy)) {
            entropy.fill(0)
            throw HeirException("check-failed", "These shards do not recover the owner's recovery phrase")
        }
        return entropy
    }

    /** `lgkheir:` + unpadded base64url of the package bytes; the package is verified first. */
    fun shardQrText(pkg: ByteArray): String {
        readPackage(pkg)
        val text = QR_PREFIX + Base64Url.encodeNoPad(pkg)
        if (text.length > QR_LIMIT) throw HeirException("invalid", "This shard is too large for one QR code")
        return text
    }

    private val QR_BODY = Regex("[A-Za-z0-9_-]+")

    /** The package bytes of a scanned `lgkheir:` text (verified). */
    fun packageFromQrText(text: String): ByteArray {
        fun no(): Nothing = throw HeirException("malformed", "This QR code is not an emergency access shard")
        if (!text.startsWith(QR_PREFIX) || text.length > QR_LIMIT) no()
        val body = text.substring(QR_PREFIX.length)
        if (!QR_BODY.matches(body) || body.length % 4 == 1) no()
        val data = Base64Url.decodeLenient(body, QR_LIMIT) ?: no()
        readPackage(data)
        return data
    }

    // ---- the plan record ------------------------------------------------------------------

    /**
     * Parses a plan record: the desktop's stored form (with `folder`, optional `home`) or the synced form a phone
     * keeps. Throws [HeirException] `malformed` for anything the desktop's `_parse` refuses.
     */
    fun parsePlan(record: JsonValue?): HeirPlan {
        try {
            val r = (record as? JsonValue.Obj)?.fields ?: bad()
            val optional = setOf("stale", "denied", "home", "folder")
            if (r.keys - optional != RECORD_KEYS - "folder" || r["version"] != JsonValue.Int(VERSION)) bad()
            val stale = r["stale"] ?: JsonValue.Bool(false)
            val home = r["home"] ?: JsonValue.Bool(true)
            if (stale !is JsonValue.Bool || home !is JsonValue.Bool) bad()
            val folder = r["folder"]
            if (folder != null && folder != JsonValue.Null && folder !is JsonValue.Str) bad()
            checkCounts(r["k"], r["n"], r["wait_days"])
            val n = int(r["n"])
            val names = holders(r["holders"], n)
            val seed = Envelope.b64d(r["signing_key"], 32)
            val signer = Envelope.b64d(r["signer"], 32)
            if (!Ed25519.publicKey(seed).contentEquals(signer) || !isInt(r["created"])) bad()
            val owner = (r["owner"] as? JsonValue.Str)?.v ?: bad()
            if (printable(owner, OWNER_LIMIT, allowEmpty = true) != owner) bad()
            val keys = (r["holder_keys"] as? JsonValue.Arr)?.items ?: bad()
            if (keys.size.toLong() != n) bad()
            val holderKeys = keys.map { Envelope.b64d(it, 32) }
            val denied = r["denied"]?.let { (it as? JsonValue.Arr)?.items ?: bad() } ?: emptyList()
            if (denied.size > DENIED_LIMIT) bad()
            return HeirPlan(
                Envelope.checkedId(r["plan_id"]), int(r["k"]).toInt(), n.toInt(), names, int(r["wait_days"]).toInt(),
                int(r["created"]), owner, signer, seed, Envelope.b64d(r["check_salt"], 16), Envelope.b64d(r["check"], 32),
                Envelope.b64d(r["backup_public"], 32), holderKeys, stale.v, denied.map { Envelope.checkedId(it) },
            )
        } catch (e: EnvelopeException) {
            throw HeirException("malformed", "The stored emergency access plan is damaged")
        } catch (e: HeirException) {
            throw HeirException("malformed", "The stored emergency access plan is damaged")
        } catch (e: IllegalArgumentException) {
            throw HeirException("malformed", "The stored emergency access plan is damaged")
        }
    }

    /** The synced form of a record: no local-only keys, `stale` and `denied` always present (desktop `synced_record`). */
    fun syncedRecord(record: JsonValue?): JsonValue.Obj {
        parsePlan(record)
        val r = (record as JsonValue.Obj).fields
        val out = LinkedHashMap(r.filterKeys { it !in LOCAL_ONLY_KEYS })
        out.putIfAbsent("stale", JsonValue.Bool(false))
        out.putIfAbsent("denied", JsonValue.Arr(emptyList()))
        return JsonValue.Obj(out)
    }

    /**
     * The synced record to keep when [remote] arrives (desktop `merge_synced`, the phone keeping only the synced form).
     * The same plan: `stale` is either side's and `denied` the union (the newest [DENIED_LIMIT]; the remote's order
     * when nothing is new); every other field is pinned (`conflict` when it differs). Another plan replaces [local].
     */
    fun mergeSynced(local: JsonValue?, remote: JsonValue?): JsonValue.Obj {
        val r = (remote as? JsonValue.Obj)?.fields
        if (r == null || r.keys != SYNCED_KEYS) throw HeirException("malformed", "The synced emergency access plan is damaged")
        val incoming = syncedRecord(remote)
        val l = (local as? JsonValue.Obj)?.fields
        if (l == null || l["plan_id"] != incoming.fields["plan_id"]) {
            parsePlan(incoming)
            return incoming
        }
        val mine = syncedRecord(local).fields
        val theirs = incoming.fields
        if ((SYNCED_KEYS - MUTABLE_KEYS).any { mine[it] != theirs[it] }) {
            throw HeirException("conflict", "The synced emergency access plan differs from this one")
        }
        val localDenied = (mine.getValue("denied") as JsonValue.Arr).items
        val remoteDenied = (theirs.getValue("denied") as JsonValue.Arr).items
        var denied = localDenied + remoteDenied.filter { it !in localDenied }
        if (denied.toSet() == remoteDenied.toSet()) denied = remoteDenied
        val stale = (mine["stale"] as JsonValue.Bool).v || (theirs["stale"] as JsonValue.Bool).v
        val stored = LinkedHashMap(theirs)
        stored["stale"] = JsonValue.Bool(stale)
        stored["denied"] = JsonValue.Arr(denied.takeLast(DENIED_LIMIT))
        val out = JsonValue.Obj(stored)
        parsePlan(out)
        return out
    }

    /**
     * [states] to publish; without [heir] the plan's state is left out (desktop `publishable(heir=...)`): it goes only to
     * peers that advertise the `heir` feature, so older apps never see a namespace they would refuse.
     */
    fun publishable(states: List<ItemState>, heir: Boolean): List<ItemState> =
        if (heir) states else states.filter { it.itemId != STATE_ID }

    /** [record] with [requestId] remembered as refused (the newest [DENIED_LIMIT] kept; desktop `add_denied`). */
    fun withDenied(record: JsonValue.Obj, requestId: String): JsonValue.Obj {
        if (!Envelope.isId(requestId)) throw HeirException("malformed")
        parsePlan(record)
        val before = (record.fields["denied"] as? JsonValue.Arr)?.items ?: emptyList()
        val denied = before.filter { it != JsonValue.Str(requestId) } + JsonValue.Str(requestId)
        return JsonValue.Obj(LinkedHashMap(record.fields).also { it["denied"] = JsonValue.Arr(denied.takeLast(DENIED_LIMIT)) })
    }
}
