package app.localgatekeys.core.share

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.sync.FolderAccess
import app.localgatekeys.core.sync.FolderLayout

/** A revoke notice that is not accepted; [reason] is the desktop `RevokeError` code. */
class RevokeException(val reason: String) : Exception(reason)

/**
 * Signed revoke notice for one `.lgkshare` package (desktop `localvault.share_revoke`, LGKSHARE v1.1): Ed25519 over
 * [LABEL] + canonical JSON of `{format, package_id, signer, issued_at}` with the sender's member signing key. The
 * notices travel in `LocalGateKeys Sync/revoked/<package id>.lgkrevoke`; verified ids go to [Share.open] `revoked`.
 */
object ShareRevoke {
    val LABEL: ByteArray = "localgatekeys|share|revoke-notice|v1|".toByteArray(Charsets.UTF_8)
    const val FORMAT: Long = 1
    const val MAX_BYTES = 1024
    const val DIR_NAME = "revoked"
    const val DIR = "${FolderLayout.SYNC_DIR}/$DIR_NAME"
    const val SUFFIX = ".lgkrevoke"
    const val MAX_NOTICES = 512
    private val FIELDS = setOf("format", "package_id", "signer", "issued_at", "sig")
    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    private fun packageId(v: JsonValue?): String {
        val s = (v as? JsonValue.Str)?.v ?: throw RevokeException("bad-revoke")
        if (!UUID_RE.matches(s)) throw RevokeException("bad-revoke")
        return s
    }

    private fun canonical(v: Map<String, JsonValue>): ByteArray = CanonicalJson.encode(JsonValue.Obj(v), Dialect.UTF8)

    /** The notice bytes (desktop `make_revoke`); [seed] is the 32-byte Ed25519 signing seed. */
    fun make(seed: ByteArray, packageId: String, signer: String, now: Long): ByteArray {
        val body = linkedMapOf<String, JsonValue>(
            "format" to JsonValue.Int(FORMAT),
            "package_id" to JsonValue.Str(packageId(JsonValue.Str(packageId))),
            "signer" to JsonValue.Str(signer.take(64)),
            "issued_at" to JsonValue.Int(now),
        )
        val sig = Ed25519.sign(seed, LABEL + canonical(body))
        return canonical(body + ("sig" to JsonValue.Str(Base64Std.encode(sig))))
    }

    private fun parse(raw: ByteArray): Map<String, JsonValue> {
        if (raw.size > MAX_BYTES) throw RevokeException("bad-revoke")
        val doc = try {
            CanonicalJson.parse(raw)
        } catch (e: Exception) {
            throw RevokeException("bad-revoke")
        }
        val f = (doc as? JsonValue.Obj)?.fields ?: throw RevokeException("bad-revoke")
        if (f.keys != FIELDS || f["format"] != JsonValue.Int(FORMAT) || f["issued_at"] !is JsonValue.Int ||
            f["signer"] !is JsonValue.Str || f["sig"] !is JsonValue.Str
        ) {
            throw RevokeException("bad-revoke")
        }
        return f
    }

    /** The revoked package id; [RevokeException] `bad-revoke`, `other-package` or `bad-signature` (desktop `verify_revoke`). */
    fun verify(raw: ByteArray, publicKey: ByteArray, packageId: String): String {
        val f = parse(raw)
        if (packageId(f["package_id"]) != packageId) throw RevokeException("other-package")
        val sig = try {
            Base64Std.decodeStrict((f["sig"] as JsonValue.Str).v)
        } catch (e: Exception) {
            throw RevokeException("bad-revoke")
        }
        val ok = try {
            publicKey.size == 32 && sig.size == 64 && Ed25519.verify(sig, LABEL + canonical(f.filterKeys { it != "sig" }), publicKey)
        } catch (e: Exception) {
            false
        }
        if (!ok) throw RevokeException("bad-signature")
        return packageId
    }

    /**
     * Package ids revoked by a trusted member ([trusted]: device id -> base64 Ed25519 public key). [files]: (name,
     * bytes) of the `revoked/` folder; at most [MAX_NOTICES] names ending [SUFFIX], in name order. Never throws.
     */
    fun collect(files: List<Pair<String, ByteArray>>, trusted: Map<String, String>): Set<String> {
        val out = LinkedHashSet<String>()
        for ((_, raw) in files.filter { it.first.endsWith(SUFFIX) }.sortedBy { it.first }.take(MAX_NOTICES)) {
            try {
                val f = parse(raw)
                val key = trusted[(f["signer"] as JsonValue.Str).v] ?: continue
                out += verify(raw, Base64Std.decodeStrict(key), (f["package_id"] as? JsonValue.Str)?.v ?: continue)
            } catch (e: Exception) {
                continue
            }
        }
        return out
    }

    /** [collect] over the cloud folder's `LocalGateKeys Sync/revoked/`. Never throws: no folder means none. */
    fun collect(access: FolderAccess, trusted: Map<String, String>): Set<String> {
        if (trusted.isEmpty()) return emptySet()
        val names = try {
            access.list(DIR).filter { it.endsWith(SUFFIX) }.sorted().take(MAX_NOTICES)
        } catch (e: Exception) {
            return emptySet()
        }
        val files = names.mapNotNull { name ->
            try {
                access.read("$DIR/$name", MAX_BYTES + 1).takeIf { it.size <= MAX_BYTES }?.let { name to it }
            } catch (e: Exception) {
                null
            }
        }
        return collect(files, trusted)
    }
}
