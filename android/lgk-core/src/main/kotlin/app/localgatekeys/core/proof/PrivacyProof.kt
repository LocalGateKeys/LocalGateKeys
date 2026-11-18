package app.localgatekeys.core.proof

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.Hex
import java.security.MessageDigest

/**
 * The privacy proof file (feature pack contract 2026-11-15 §5): facts read from this device, the claims this platform
 * may make, and an Ed25519 signature by the sync device identity (or none when sync is off). A signature proves only
 * that the file was not changed after this device made it; it does not prove the claims.
 */
object PrivacyProof {
    const val FORMAT = "lgk-privacy-proof"
    const val VERSION = 2L
    val PREFIX: ByteArray = "localgatekeys|privacy-proof|v2|".toByteArray(Charsets.UTF_8)
    private val TOP_KEYS = setOf("format", "version", "generated_at", "app", "facts", "claims", "network", "signature")

    /** What the page reads from the device ([sync]: `off`, `folder`, `wifi` or `both`). */
    data class Facts(
        val sync: String,
        val devices: Long,
        val shares: Long,
        val items: Long,
        val breachChecks: Boolean,
        val strictOffline: Boolean,
        val updateCheck: Boolean,
    ) {
        fun json(): JsonValue = JsonValue.Obj(
            mapOf(
                "sync" to JsonValue.Str(sync), "devices" to JsonValue.Int(devices), "shares" to JsonValue.Int(shares),
                "items" to JsonValue.Int(items), "breach_checks" to JsonValue.Bool(breachChecks),
                "strict_offline" to JsonValue.Bool(strictOffline), "update_check" to JsonValue.Bool(updateCheck),
            ),
        )
    }

    /**
     * The unsigned document. Android has no network guard test yet, so the list is unavailable (`available: false`,
     * empty entries and counts) and [claims] holds only what this platform's tests back.
     */
    fun document(generatedAt: String, platform: String, version: String, facts: Facts, claims: List<String>): Map<String, JsonValue> = linkedMapOf(
        "format" to JsonValue.Str(FORMAT),
        "version" to JsonValue.Int(VERSION),
        "generated_at" to JsonValue.Str(generatedAt),
        "app" to JsonValue.Obj(mapOf("platform" to JsonValue.Str(platform), "version" to JsonValue.Str(version))),
        "facts" to facts.json(),
        "claims" to JsonValue.Arr(claims.map { JsonValue.Str(it) }),
        "network" to JsonValue.Obj(
            mapOf(
                "available" to JsonValue.Bool(false), "since" to JsonValue.Null,
                "entries" to JsonValue.Arr(emptyList()), "counts" to JsonValue.Obj(emptyMap()),
            ),
        ),
    )

    /**
     * The bytes a signature covers (version 2): the domain prefix plus the canonical document with only
     * `signature.value` removed, so `signature.alg`, `device_id` and `public_key` are signed.
     */
    fun signedBytes(doc: Map<String, JsonValue>): ByteArray {
        val body = LinkedHashMap(doc)
        (doc["signature"] as? JsonValue.Obj)?.let { body["signature"] = JsonValue.Obj(it.fields - "value") }
        return PREFIX + CanonicalJson.encode(JsonValue.Obj(body), Dialect.UTF8)
    }

    /** First 8 bytes of SHA-256 of the raw public key, as 16 lower-case hex digits. */
    fun fingerprint(publicKey: ByteArray): String = Hex.lower(MessageDigest.getInstance("SHA-256").digest(publicKey).copyOf(8))

    /** [doc] signed by [identity], or with `signature: null` when there is none (sync off). */
    fun sign(doc: Map<String, JsonValue>, identity: DeviceIdentity?): Map<String, JsonValue> {
        val out = LinkedHashMap(doc - "signature")
        if (identity == null) {
            out["signature"] = JsonValue.Null
            return out
        }
        val head = linkedMapOf<String, JsonValue>(
            "alg" to JsonValue.Str("Ed25519"),
            "device_id" to JsonValue.Str(identity.deviceId),
            "public_key" to JsonValue.Str(Base64Std.encode(identity.signingPublicKey)),
        )
        out["signature"] = JsonValue.Obj(head)
        head["value"] = JsonValue.Str(Base64Std.encode(identity.sign(signedBytes(out))))
        out["signature"] = JsonValue.Obj(head)
        return out
    }

    /** The file's bytes (canonical JSON, UTF-8). */
    fun encode(doc: Map<String, JsonValue>): ByteArray = CanonicalJson.encode(JsonValue.Obj(doc), Dialect.UTF8)

    fun fileName(today: String): String = "LocalGateKeys-privacy-proof-$today.json"

    enum class Status { VALID, UNSIGNED, INVALID }

    data class Verdict(val status: Status, val deviceId: String = "", val fingerprint: String = "")

    /** `lgk proof verify`: strict parse (duplicate keys refused), exact top-level keys, version 2 only (a version-1 file is an old, invalid file), then the strict signature check. */
    fun verify(bytes: ByteArray): Verdict {
        val doc = try {
            (CanonicalJson.parse(bytes) as? JsonValue.Obj)?.fields
        } catch (e: Exception) {
            null
        } ?: return Verdict(Status.INVALID)
        if (doc.keys != TOP_KEYS) return Verdict(Status.INVALID)
        if (doc["format"] != JsonValue.Str(FORMAT) || doc["version"] != JsonValue.Int(VERSION)) return Verdict(Status.INVALID)
        val sig = doc["signature"]
        if (sig == JsonValue.Null) return Verdict(Status.UNSIGNED)
        val s = (sig as? JsonValue.Obj)?.fields ?: return Verdict(Status.INVALID)
        if (s.keys != setOf("alg", "device_id", "public_key", "value") || s["alg"] != JsonValue.Str("Ed25519")) return Verdict(Status.INVALID)
        val deviceId = (s["device_id"] as? JsonValue.Str)?.v ?: return Verdict(Status.INVALID)
        return try {
            val pub = Base64Std.decodeStrict((s["public_key"] as JsonValue.Str).v)
            val value = Base64Std.decodeStrict((s["value"] as JsonValue.Str).v)
            if (pub.size != 32 || value.size != 64) return Verdict(Status.INVALID)
            if (Ed25519.verifyStrict(value, signedBytes(doc), pub)) Verdict(Status.VALID, deviceId, fingerprint(pub)) else Verdict(Status.INVALID)
        } catch (e: Exception) {
            Verdict(Status.INVALID)
        }
    }
}
