package app.localgatekeys.core.recovery

import app.localgatekeys.core.crypto.Bip39
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.primitives.CryptoBox
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.X25519
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderAccessException
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * `reason`: `no-folder`, `no-plan`, `no-request`, `denied`, `waiting` ([daysLeft]), `need-more` ([missing]),
 * `no-backup`, `check-failed`, `stale-plan`, `malformed`, `mixed-plans`, `duplicate` or `wrong-phrase`
 * (desktop `heir_flow.HeirFlowError`).
 */
class HeirFlowException(val reason: String, val missing: Int = 0, val daysLeft: Int = 0) : Exception(reason)

/** A requester's keys, kept in the requester's own encrypted vault: Ed25519 signs requests, X25519 receives a grant. */
class RequesterIdentity(signingSeed: ByteArray, boxKey: ByteArray) {
    private val seed = signingSeed.copyOf()
    private val box = boxKey.copyOf()

    init {
        require(seed.size == 32 && box.size == 32) { "bad key length" }
    }

    val signer: ByteArray get() = Ed25519.publicKey(seed)
    val boxPublic: ByteArray get() = X25519.publicKey(box)

    internal fun signingSeed(): ByteArray = seed.copyOf()
    internal fun boxKey(): ByteArray = box.copyOf()

    /** `{"version": 1, "signing_key", "box_key"}` (desktop `RequesterIdentity.to_record`). */
    fun toRecord(): JsonValue.Obj = JsonValue.Obj(
        mapOf(
            "version" to JsonValue.Int(1),
            "signing_key" to JsonValue.Str(Envelope.b64e(seed)),
            "box_key" to JsonValue.Str(Envelope.b64e(box)),
        ),
    )

    fun wipe() {
        seed.fill(0)
        box.fill(0)
    }

    override fun toString(): String = "RequesterIdentity"

    companion object {
        fun generate(random: RandomSource): RequesterIdentity {
            val s = random.bytes(32)
            val b = random.bytes(32)
            try {
                return RequesterIdentity(s, b)
            } finally {
                s.fill(0)
                b.fill(0)
            }
        }

        fun fromRecord(record: JsonValue?): RequesterIdentity {
            val r = (record as? JsonValue.Obj)?.fields
            if (r == null || r.keys != setOf("version", "signing_key", "box_key") || r["version"] != JsonValue.Int(1)) {
                throw HeirFlowException("malformed")
            }
            return try {
                RequesterIdentity(Envelope.b64d(r["signing_key"], 32), Envelope.b64d(r["box_key"], 32))
            } catch (e: EnvelopeException) {
                throw HeirFlowException("malformed")
            }
        }
    }
}

/** One verified access request in the folder; [holder], [daysLeft] and [granted] are filled for the owner's list. */
class HeirRequest(
    val requestId: String,
    val planId: String,
    val holderIndex: Int,
    val requester: String,
    signer: ByteArray,
    boxPublic: ByteArray,
    val created: Long,
    proof: ByteArray,
    val holder: String = "",
    val daysLeft: Int = 0,
    val granted: Boolean = false,
) {
    private val signerBytes = signer.copyOf()
    private val boxBytes = boxPublic.copyOf()
    private val proofBytes = proof.copyOf()
    val signer: ByteArray get() = signerBytes.copyOf()
    val boxPublic: ByteArray get() = boxBytes.copyOf()
    internal val proof: ByteArray get() = proofBytes.copyOf()

    internal fun listed(holder: String, daysLeft: Int, granted: Boolean) = HeirRequest(
        requestId, planId, holderIndex, requester, signerBytes, boxBytes, created, proofBytes, holder, daysLeft, granted,
    )

    override fun toString(): String = "HeirRequest($requestId)"
}

/** The owner's open requests (newest first), plus [flooded]: too many request files to read them all. */
class Pending(val requests: List<HeirRequest>, val flooded: Boolean = false)

/**
 * What the requester's screen says: `none` (ask first), `denied`, `need-more` ([missing]), `waiting` ([daysLeft]),
 * `no-backup` or `ready` (desktop `heir_flow.Status`).
 */
data class HeirStatus(
    val state: String,
    val planId: String = "",
    val owner: String = "",
    val k: Int = 0,
    val have: Int = 0,
    val requestId: String = "",
    val daysLeft: Int = 0,
    val missing: Int = 0,
    val granted: Boolean = false,
)

/**
 * The heir folder, a folder the owner shares with the holders (a cloud drive the phone reaches through the Storage
 * Access Framework). [rootName] is the picked folder's own name: picking `LocalGateKeys Emergency` itself also works, as
 * on the desktop (`plan_dir`).
 */
class HeirFolder(val access: FolderAccess, val rootName: String? = null)

/**
 * Emergency access flows with no server: port of `src/localvault/heir_flow.py` (byte rules in
 * `docs/formats/LGKHEIR_V1.md` "Folder flow"). Every file in `<folder>/LocalGateKeys Emergency/<plan id>/` is a signed
 * envelope with its own `kind` and exact payload keys; nothing in the folder is trusted.
 *
 * A phone takes part as one of the owner's devices (the plan arrives by sync: list requests, deny, grant now with the
 * typed phrase) and as a holder (ask for access, follow the status, then recover and check the owner's recovery phrase).
 * The owner's backups in the folder are written and restored by the computer; a phone only reads their signed
 * descriptors to tell whether one is there. Times are integer Unix seconds from the caller.
 */
object HeirFlow {
    const val FOLDER_NAME = "LocalGateKeys Emergency"
    const val DAY = 86_400L
    const val REQUEST_SUFFIX = ".lgkheirreq"
    const val DENY_SUFFIX = ".lgkheirdeny"
    const val GRANT_SUFFIX = ".lgkheirgrant"
    const val DESCRIPTOR_SUFFIX = ".lgkheirbackup"
    const val BACKUP_SUFFIX = ".lgk"
    private val HEIR_SUFFIXES = listOf(".lgkheir", REQUEST_SUFFIX, DENY_SUFFIX, GRANT_SUFFIX, DESCRIPTOR_SUFFIX)
    const val REQUEST_KIND = "heir-request"
    const val DENY_KIND = "heir-deny"
    const val GRANT_KIND = "heir-grant"
    const val BACKUP_KIND = "heir-backup"
    const val MAX_FILE = 8192
    const val MAX_SCAN = 512
    const val MAX_REQUEST_SCAN = 4096
    val PROOF_CONTEXT: ByteArray = "LocalGateKeys heir request v1\n".toByteArray(Charsets.US_ASCII)
    val GRANT_INFO: ByteArray = "LocalGateKeys heir grant v1\n".toByteArray(Charsets.US_ASCII)
    private const val UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    private val BACKUP_NAME = Regex("backup-\\d{8}-\\d{6}-[0-9a-f]{8}")
    private val REQUEST_NAME = Regex("request-$UUID\\$REQUEST_SUFFIX")
    private val DENY_NAME = Regex("deny-($UUID)[ ()A-Za-z0-9_-]{0,40}\\$DENY_SUFFIX")
    private val GRANT_NAME = Regex("grant-($UUID)[ ()A-Za-z0-9_-]{0,40}\\$GRANT_SUFFIX")
    private val DESCRIPTOR_NAME = Regex("backup-\\d{8}-\\d{6}-[0-9a-f]{8}\\$DESCRIPTOR_SUFFIX")
    private val HEX64 = Regex("[0-9a-f]{64}")
    private val REQUEST_FIELDS = setOf("kind", "plan_id", "holder_index", "box_public", "created", "proof")
    private val DENY_FIELDS = setOf("kind", "plan_id", "request_id", "created")
    private val GRANT_FIELDS = setOf("kind", "plan_id", "request_id", "box_public", "ephemeral", "wrapped", "created")
    private val BACKUP_FIELDS = setOf("kind", "plan_id", "file", "size", "sha256", "written_at", "backup_public")
    private const val MAX_TIME = (1L shl 53) - 1

    // ---- the folder -----------------------------------------------------------------------

    /** `LocalGateKeys Emergency/<plan id>` inside [folder] (`<plan id>` when the picked folder is the emergency folder). */
    fun planDir(folder: HeirFolder, planId: String): String {
        if (!Envelope.isId(planId)) throw HeirFlowException("malformed")
        return if (folder.rootName == FOLDER_NAME) planId else "$FOLDER_NAME/$planId"
    }

    private fun join(dir: String, name: String) = if (dir.isEmpty()) name else "$dir/$name"

    /** Whether a folder entry belongs to emergency access (the folder sync ignores these). */
    fun isHeirFile(name: String): Boolean {
        if (name == FOLDER_NAME || HEIR_SUFFIXES.any { name.endsWith(it) }) return true
        return name.endsWith(BACKUP_SUFFIX) && BACKUP_NAME.matches(name.dropLast(BACKUP_SUFFIX.length))
    }

    private fun write(folder: HeirFolder, path: String, data: ByteArray) {
        try {
            folder.access.writeAtomic(path, data)
        } catch (e: FolderAccessException) {
            throw HeirFlowException("no-folder")
        } catch (e: RuntimeException) {
            throw HeirFlowException("no-folder")
        }
    }

    private fun readSmall(folder: HeirFolder, path: String, limit: Int = MAX_FILE): ByteArray? = try {
        folder.access.read(path, limit + 1).takeIf { it.size <= limit }
    } catch (e: Exception) {
        null
    }

    private fun entries(folder: HeirFolder, dir: String, pattern: Regex, cap: Int = MAX_SCAN): List<String> = try {
        folder.access.list(dir).filter { pattern.matches(it) }.sorted().take(cap).map { join(dir, it) }
    } catch (e: Exception) {
        emptyList()
    }

    private fun flooded(folder: HeirFolder, dir: String): Boolean = try {
        folder.access.list(dir).count { REQUEST_NAME.matches(it) } > MAX_REQUEST_SCAN
    } catch (e: Exception) {
        false
    }

    /** A signed heir file of [kind] with exactly [fields], or null (never throws). */
    private fun open(data: ByteArray?, kind: String, fields: Set<String>): SignedEnvelope? {
        if (data == null) return null
        val opened = try {
            Envelope.open(data, Heir.FORMAT, Heir.VERSION, MAX_FILE)
        } catch (e: EnvelopeException) {
            return null
        }
        if (opened.payload.keys != fields || opened.payload["kind"] != JsonValue.Str(kind)) return null
        return opened
    }

    private fun signed(payload: Map<String, JsonValue>, seed: ByteArray, packageId: String, sender: String = ""): ByteArray =
        Envelope.seal(Heir.FORMAT, Heir.VERSION, packageId, sender, payload, seed)

    private fun isTime(v: JsonValue?): Boolean = v is JsonValue.Int && v.v in 0..MAX_TIME

    private fun daysLeft(deadline: Long, now: Long): Int =
        if (deadline <= now) 0 else ((deadline - now + DAY - 1) / DAY).toInt()

    private fun same(a: ByteArray, b: ByteArray) = MessageDigest.isEqual(a, b)

    // ---- requests -------------------------------------------------------------------------

    private fun proofMessage(planId: String, requestId: String, holderIndex: Int, signer: ByteArray, boxPublic: ByteArray, created: Long): ByteArray =
        PROOF_CONTEXT + Envelope.canonical(
            JsonValue.Obj(
                mapOf(
                    "plan_id" to JsonValue.Str(planId),
                    "request_id" to JsonValue.Str(requestId),
                    "holder_index" to JsonValue.Int(holderIndex.toLong()),
                    "signer" to JsonValue.Str(Envelope.b64e(signer)),
                    "box_public" to JsonValue.Str(Envelope.b64e(boxPublic)),
                    "created" to JsonValue.Int(created),
                ),
            ),
        )

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    private fun proof(key: ByteArray, planId: String, requestId: String, holderIndex: Int, signer: ByteArray, boxPublic: ByteArray, created: Long) =
        hmac(key, proofMessage(planId, requestId, holderIndex, signer, boxPublic, created))

    private fun readRequest(folder: HeirFolder, path: String, planId: String): HeirRequest? {
        val opened = open(readSmall(folder, path), REQUEST_KIND, REQUEST_FIELDS) ?: return null
        val p = opened.payload
        val index = (p["holder_index"] as? JsonValue.Int)?.v ?: return null
        if (p["plan_id"] != JsonValue.Str(planId) || index !in 1..5 || !isTime(p["created"])) return null
        return try {
            HeirRequest(
                opened.id, planId, index.toInt(), opened.sender, opened.signer, Envelope.b64d(p["box_public"], 32),
                (p["created"] as JsonValue.Int).v, Envelope.b64d(p["proof"], 32),
            )
        } catch (e: EnvelopeException) {
            null
        }
    }

    private fun requests(folder: HeirFolder, dir: String, planId: String): List<HeirRequest> =
        entries(folder, dir, REQUEST_NAME, MAX_REQUEST_SCAN).mapNotNull { readRequest(folder, it, planId) }
            .sortedWith(compareByDescending<HeirRequest> { it.created }.thenByDescending { it.requestId })

    /** The request file a holder writes for the plan of [shard] (their package); [requestId] is its envelope id. */
    fun requestBytes(shard: ByteArray, identity: RequesterIdentity, requestId: String, created: Long): ByteArray {
        val holderShard = readShard(shard)
        if (!Envelope.isId(requestId) || created !in 0..MAX_TIME) throw HeirFlowException("malformed")
        val box = identity.boxPublic
        val share = holderShard.share
        val key = Heir.holderKey(share, holderShard.planId, holderShard.checkSalt)
        share.fill(0)
        val mac = try {
            proof(key, holderShard.planId, requestId, holderShard.index, identity.signer, box, created)
        } finally {
            key.fill(0)
        }
        val payload = mapOf(
            "kind" to JsonValue.Str(REQUEST_KIND),
            "plan_id" to JsonValue.Str(holderShard.planId),
            "holder_index" to JsonValue.Int(holderShard.index.toLong()),
            "box_public" to JsonValue.Str(Envelope.b64e(box)),
            "created" to JsonValue.Int(created),
            "proof" to JsonValue.Str(Envelope.b64e(mac)),
        )
        val seed = identity.signingSeed()
        try {
            return signed(payload, seed, requestId, holderShard.holder)
        } finally {
            seed.fill(0)
        }
    }

    /** Writes a signed access request for the plan of [shard] into the folder; returns its path. */
    fun requestAccess(folder: HeirFolder, shard: ByteArray, identity: RequesterIdentity, now: Long, random: RandomSource): String {
        val planId = readShard(shard).planId
        val requestId = KeyringRotate.uuid4(random)
        val path = join(planDir(folder, planId), "request-$requestId$REQUEST_SUFFIX")
        write(folder, path, requestBytes(shard, identity, requestId, now))
        return path
    }

    private fun readShard(data: ByteArray): Shard = try {
        Heir.readPackage(data)
    } catch (e: HeirException) {
        throw fromHeir(e)
    }

    private fun fromHeir(e: HeirException): HeirFlowException = when (e.reason) {
        "need-more" -> HeirFlowException("need-more", missing = e.missing)
        "check-failed", "mixed-plans", "duplicate" -> HeirFlowException(e.reason)
        else -> HeirFlowException("malformed")
    }

    // ---- deny and grant files -------------------------------------------------------------

    private fun validDeny(folder: HeirFolder, path: String, signer: ByteArray, planId: String): String? {
        val opened = open(readSmall(folder, path), DENY_KIND, DENY_FIELDS) ?: return null
        if (!same(opened.signer, signer) || opened.payload["plan_id"] != JsonValue.Str(planId)) return null
        return (opened.payload["request_id"] as? JsonValue.Str)?.v
    }

    private fun denials(folder: HeirFolder, dir: String, signer: ByteArray, planId: String): Set<String> =
        entries(folder, dir, DENY_NAME).mapNotNull { validDeny(folder, it, signer, planId) }.toSet()

    /** Any valid deny for this request by the plan key, whatever its time (the veto); its own name is read first. */
    private fun denyPresent(folder: HeirFolder, dir: String, signer: ByteArray, planId: String, requestId: String): Boolean {
        if (validDeny(folder, join(dir, "deny-$requestId$DENY_SUFFIX"), signer, planId) == requestId) return true
        return requestId in denials(folder, dir, signer, planId)
    }

    private fun grantIndex(folder: HeirFolder, dir: String, signer: ByteArray, planId: String): Map<Pair<String, String>, List<SignedEnvelope>> {
        val out = LinkedHashMap<Pair<String, String>, MutableList<SignedEnvelope>>()
        for (path in entries(folder, dir, GRANT_NAME)) {
            val opened = open(readSmall(folder, path), GRANT_KIND, GRANT_FIELDS) ?: continue
            if (!same(opened.signer, signer) || opened.payload["plan_id"] != JsonValue.Str(planId)) continue
            val rid = (opened.payload["request_id"] as? JsonValue.Str)?.v ?: continue
            val box = (opened.payload["box_public"] as? JsonValue.Str)?.v ?: continue
            out.getOrPut(rid to box) { ArrayList() }.add(opened)
        }
        return out
    }

    private fun grantAad(planId: String, requestId: String, boxPublic: ByteArray): ByteArray =
        GRANT_INFO + Envelope.canonical(
            JsonValue.Obj(
                mapOf(
                    "plan_id" to JsonValue.Str(planId),
                    "request_id" to JsonValue.Str(requestId),
                    "box_public" to JsonValue.Str(Envelope.b64e(boxPublic)),
                ),
            ),
        )

    private fun grantKek(shared: ByteArray, ephemeral: ByteArray, boxPublic: ByteArray, planId: String, requestId: String): ByteArray {
        val info = GRANT_INFO + planId.toByteArray(Charsets.US_ASCII) + "\n".toByteArray() + requestId.toByteArray(Charsets.US_ASCII)
        return CryptoBox.hkdf(shared, ephemeral + boxPublic, info, 32)
    }

    /** The grant file: [entropy] wrapped to the request's X25519 key with the ephemeral key [ephemeralKey], signed by the plan key. */
    fun grantBytes(plan: HeirPlan, request: HeirRequest, entropy: ByteArray, now: Long, ephemeralKey: ByteArray, packageId: String): ByteArray {
        val epk = X25519.publicKey(ephemeralKey)
        val box = request.boxPublic
        val shared = X25519.agree(ephemeralKey, box)
        val kek = grantKek(shared, epk, box, plan.planId, request.requestId)
        shared.fill(0)
        val wrapped = try {
            CryptoBox.sealGcm(kek, ByteArray(12), entropy, grantAad(plan.planId, request.requestId, box))
        } finally {
            kek.fill(0)
        }
        val payload = mapOf(
            "kind" to JsonValue.Str(GRANT_KIND),
            "plan_id" to JsonValue.Str(plan.planId),
            "request_id" to JsonValue.Str(request.requestId),
            "box_public" to JsonValue.Str(Envelope.b64e(box)),
            "ephemeral" to JsonValue.Str(Envelope.b64e(epk)),
            "wrapped" to JsonValue.Str(Envelope.b64e(wrapped)),
            "created" to JsonValue.Int(now),
        )
        val seed = plan.signingSeed()
        try {
            return signed(payload, seed, packageId)
        } finally {
            seed.fill(0)
        }
    }

    /** The entropy of a grant made out to [identity], or null (the caller zeroes it). */
    fun openGrant(grant: SignedEnvelope, identity: RequesterIdentity): ByteArray? {
        val p = grant.payload
        val planId = (p["plan_id"] as? JsonValue.Str)?.v ?: return null
        val requestId = (p["request_id"] as? JsonValue.Str)?.v ?: return null
        val box = identity.boxKey()
        return try {
            val epk = Envelope.b64d(p["ephemeral"], 32)
            val wrapped = Envelope.b64d(p["wrapped"], 48)
            val shared = X25519.agree(box, epk)
            val kek = grantKek(shared, epk, identity.boxPublic, planId, requestId)
            shared.fill(0)
            try {
                CryptoBox.openGcm(kek, ByteArray(12), wrapped, grantAad(planId, requestId, identity.boxPublic))
            } finally {
                kek.fill(0)
            }
        } catch (e: Exception) {
            null
        } finally {
            box.fill(0)
        }
    }

    /** Opens a grant file's bytes (signature and fields checked) for tests and the requester's flow. */
    fun readGrant(data: ByteArray): SignedEnvelope? = open(data, GRANT_KIND, GRANT_FIELDS)

    /** The deny file for [requestId], signed by the plan key. */
    fun denyBytes(plan: HeirPlan, requestId: String, now: Long, packageId: String): ByteArray {
        val payload = mapOf(
            "kind" to JsonValue.Str(DENY_KIND),
            "plan_id" to JsonValue.Str(plan.planId),
            "request_id" to JsonValue.Str(requestId),
            "created" to JsonValue.Int(now),
        )
        val seed = plan.signingSeed()
        try {
            return signed(payload, seed, packageId)
        } finally {
            seed.fill(0)
        }
    }

    // ---- the owner's side -----------------------------------------------------------------

    private fun verified(request: HeirRequest, plan: HeirPlan): Boolean {
        if (request.planId != plan.planId || request.holderIndex !in 1..plan.n) return false
        val key = plan.holderKey(request.holderIndex)
        try {
            val expect = proof(key, request.planId, request.requestId, request.holderIndex, request.signer, request.boxPublic, request.created)
            return same(expect, request.proof)
        } finally {
            key.fill(0)
        }
    }

    private fun writeDeny(folder: HeirFolder, dir: String, plan: HeirPlan, requestId: String, now: Long, random: RandomSource): String {
        val path = join(dir, "deny-$requestId$DENY_SUFFIX")
        write(folder, path, denyBytes(plan, requestId, now, KeyringRotate.uuid4(random)))
        return path
    }

    /**
     * The owner's open requests: only those that prove a shard of this plan and are not denied. A request the owner
     * refused ([HeirPlan.denied]) whose deny file is missing gets it written again (best effort).
     */
    fun pendingFor(plan: HeirPlan, folder: HeirFolder, now: Long, random: RandomSource): Pending {
        val dir = planDir(folder, plan.planId)
        if (plan.stale) purgeBackups(folder, dir) // the replaced phrase's backups: old shards must find nothing to open
        val signer = plan.signer
        val denials = denials(folder, dir, signer, plan.planId)
        val grants = grantIndex(folder, dir, signer, plan.planId)
        val out = ArrayList<HeirRequest>()
        for (request in requests(folder, dir, plan.planId)) {
            if (!verified(request, plan)) continue
            if (request.requestId in denials) continue
            if (request.requestId in plan.denied) {
                try {
                    writeDeny(folder, dir, plan, request.requestId, now, random)
                } catch (e: HeirFlowException) {
                    // read-only or gone: the next look tries again
                }
                continue
            }
            val granted = (request.requestId to Envelope.b64e(request.boxPublic)) in grants
            out.add(request.listed(plan.holders[request.holderIndex - 1], daysLeft(request.created + plan.waitDays * DAY, now), granted))
        }
        return Pending(out, flooded(folder, dir))
    }

    /**
     * Deletes every backup file and descriptor in a plan's folder (best effort; the number deleted). Run on each look
     * at a stale plan: those backups are locked to the replaced phrase (`LGKHEIR_V1.md` "Stale plans").
     */
    fun purgeBackups(folder: HeirFolder, dir: String): Int {
        val names = try { folder.access.list(dir) } catch (e: Exception) { return 0 }
        var removed = 0
        for (name in names) {
            val backup = name.endsWith(BACKUP_SUFFIX) && BACKUP_NAME.matches(name.removeSuffix(BACKUP_SUFFIX))
            if (!backup && !DESCRIPTOR_NAME.matches(name)) continue
            try {
                folder.access.remove(join(dir, name))
                removed++
            } catch (e: Exception) {
                // read-only or locked: the next look tries again
            }
        }
        return removed
    }

    /** The request as it is in the folder now, re-verified (never the caller's copy). */
    private fun findRequest(plan: HeirPlan, folder: HeirFolder, requestId: String): Pair<String, HeirRequest> {
        if (!Envelope.isId(requestId)) throw HeirFlowException("malformed")
        val dir = planDir(folder, plan.planId)
        val found = requests(folder, dir, plan.planId).firstOrNull { it.requestId == requestId && verified(it, plan) }
            ?: throw HeirFlowException("no-request")
        return dir to found
    }

    /**
     * Refuses a request: writes a deny file signed by the plan key. The caller then keeps [Heir.withDenied] of the
     * plan record (so it is written again if it goes missing, and the refusal syncs to the owner's other devices).
     */
    fun deny(plan: HeirPlan, folder: HeirFolder, requestId: String, now: Long, random: RandomSource): String {
        if (!Envelope.isId(requestId)) throw HeirFlowException("malformed")
        return writeDeny(folder, planDir(folder, plan.planId), plan, requestId, now, random)
    }

    /**
     * "Grant now" from a phone (the plan arrived by sync, so the plan's check decides the typed phrase). The caller
     * re-authenticates the owner first. Order: the request (still in the folder, proving a shard), not denied, plan
     * current, then the phrase against the plan's HKDF check (`wrong-phrase`).
     */
    fun grantNow(plan: HeirPlan, folder: HeirFolder, requestId: String, phrase: String, now: Long, random: RandomSource): String {
        val (dir, found) = findRequest(plan, folder, requestId)
        if (found.requestId in plan.denied || denyPresent(folder, dir, plan.signer, plan.planId, found.requestId)) {
            throw HeirFlowException("denied")
        }
        if (plan.stale) throw HeirFlowException("stale-plan")
        val entropy = try {
            Bip39.entropy(phrase)
        } catch (e: Exception) {
            throw HeirFlowException("wrong-phrase")
        }
        val ephemeral = random.bytes(32)
        try {
            if (!Heir.verifyEntropy(plan, entropy)) throw HeirFlowException("wrong-phrase")
            val data = grantBytes(plan, found, entropy, now, ephemeral, KeyringRotate.uuid4(random))
            val path = join(dir, "grant-${found.requestId}$GRANT_SUFFIX")
            write(folder, path, data)
            return path
        } finally {
            entropy.fill(0)
            ephemeral.fill(0)
        }
    }

    // ---- the owner's backups (read only on a phone) -----------------------------------------

    /** One valid backup descriptor by the plan key. */
    class BackupInfo(val file: String, val size: Long, val sha256: String, val writtenAt: Long, val backupPublic: ByteArray)

    /** Valid descriptors by the plan key, newest first. */
    fun backups(folder: HeirFolder, dir: String, signer: ByteArray, planId: String): List<BackupInfo> {
        val out = ArrayList<BackupInfo>()
        for (path in entries(folder, dir, DESCRIPTOR_NAME)) {
            val opened = open(readSmall(folder, path), BACKUP_KIND, BACKUP_FIELDS) ?: continue
            if (!same(opened.signer, signer)) continue
            val p = opened.payload
            val name = (p["file"] as? JsonValue.Str)?.v ?: continue
            val size = (p["size"] as? JsonValue.Int)?.v ?: continue
            val sha = (p["sha256"] as? JsonValue.Str)?.v ?: continue
            if (p["plan_id"] != JsonValue.Str(planId) || !name.endsWith(BACKUP_SUFFIX) ||
                !BACKUP_NAME.matches(name.dropLast(BACKUP_SUFFIX.length)) || !isTime(p["written_at"]) || size <= 0 ||
                !HEX64.matches(sha)
            ) continue
            val public = try {
                Envelope.b64d(p["backup_public"], 32)
            } catch (e: EnvelopeException) {
                continue
            }
            out.add(BackupInfo(name, size, sha, (p["written_at"] as JsonValue.Int).v, public))
        }
        return out.sortedWith(compareByDescending<BackupInfo> { it.writtenAt }.thenByDescending { it.file })
    }

    // ---- the requester's side -------------------------------------------------------------

    private class Evaluation(val status: HeirStatus, val shards: List<Shard>, val dir: String, val request: HeirRequest?, val grant: SignedEnvelope?)

    private fun evaluate(folder: HeirFolder, packages: List<ByteArray>, identity: RequesterIdentity, now: Long): Evaluation {
        val shards = try {
            Heir.checkShards(packages)
        } catch (e: HeirException) {
            throw fromHeir(e)
        }
        val base = shards[0]
        val dir = planDir(folder, base.planId)
        val signer = identity.signer
        val box = identity.boxPublic
        val baseSigner = base.signer
        fun status(state: String, requestId: String = "", daysLeft: Int = 0, missing: Int = 0, granted: Boolean = false) =
            HeirStatus(state, base.planId, base.owner, base.k, shards.size, requestId, daysLeft, missing, granted)
        val mine = requests(folder, dir, base.planId).filter { same(it.signer, signer) && same(it.boxPublic, box) }
        val request = mine.firstOrNull() ?: return Evaluation(status("none"), shards, dir, null, null)
        val rid = request.requestId
        if (denyPresent(folder, dir, baseSigner, base.planId, rid)) return Evaluation(status("denied", rid), shards, dir, request, null)
        val grant = grantIndex(folder, dir, baseSigner, base.planId)[rid to Envelope.b64e(box)]?.firstOrNull()
        if (grant == null) {
            if (shards.size < base.k) return Evaluation(status("need-more", rid, missing = base.k - shards.size), shards, dir, request, null)
            val left = daysLeft(request.created + base.waitDays * DAY, now)
            if (left > 0) return Evaluation(status("waiting", rid, daysLeft = left), shards, dir, request, null)
        }
        val backup = backups(folder, dir, baseSigner, base.planId).any { it.writtenAt >= base.created }
        return Evaluation(status(if (backup) "ready" else "no-backup", rid, granted = grant != null), shards, dir, request, grant)
    }

    /** Where the requester stands (reads the folder; recovers nothing). */
    fun requestStatus(folder: HeirFolder, packages: List<ByteArray>, identity: RequesterIdentity, now: Long): HeirStatus =
        evaluate(folder, packages, identity, now).status

    /**
     * The owner's recovery entropy for a requester whose access is open (a grant, or `k` shards once the waiting
     * period is over), checked against the plan's HKDF check before it is returned and with the veto read again last.
     * The caller shows the phrase ([Bip39.phrase]) and zeroes the bytes. Refused: `no-request`, `denied`,
     * `need-more`, `waiting`, `malformed` (a grant that does not open), `check-failed`, `no-backup` (no descriptor newer
     * than the plan locked to this entropy's backup key, as the desktop's restore requires).
     */
    fun recoverEntropy(folder: HeirFolder, packages: List<ByteArray>, identity: RequesterIdentity, now: Long): ByteArray {
        val e = evaluate(folder, packages, identity, now)
        when (e.status.state) {
            "none" -> throw HeirFlowException("no-request")
            "denied" -> throw HeirFlowException("denied")
            "need-more" -> throw HeirFlowException("need-more", missing = e.status.missing)
            "waiting" -> throw HeirFlowException("waiting", daysLeft = e.status.daysLeft)
            // The desktop restores only a backup newer than the plan; the phone reveals nothing without one (Ruling T2-M1:
            // after the owner replaces the phrase, old shards must not open anything).
            "no-backup" -> throw HeirFlowException("no-backup")
        }
        val base = e.shards[0]
        val request = e.request ?: throw HeirFlowException("no-request")
        val entropy = if (e.grant != null) {
            openGrant(e.grant, identity) ?: throw HeirFlowException("malformed")
        } else {
            try {
                Heir.combinePackages(packages)
            } catch (x: HeirException) {
                throw fromHeir(x)
            }
        }
        // The recovered secret is checked against the plan's HKDF check before anything uses it.
        if (!Heir.verifyEntropy(base, entropy)) {
            entropy.fill(0)
            throw HeirFlowException("check-failed")
        }
        // As the desktop's `_open_backup`: a descriptor newer than the plan whose backup is locked to this entropy's
        // backup key. A replaced phrase (a new plan or new backups under another key) leaves old shards with nothing.
        val expected = Heir.backupPublicKey(entropy, base.planId, base.checkSalt)
        val locked = backups(folder, e.dir, base.signer, base.planId).any { it.writtenAt >= base.created && same(it.backupPublic, expected) }
        if (!locked) {
            entropy.fill(0)
            throw HeirFlowException("no-backup")
        }
        if (denyPresent(folder, e.dir, base.signer, base.planId, request.requestId)) {
            entropy.fill(0)
            throw HeirFlowException("denied")
        }
        return entropy
    }
}
