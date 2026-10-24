package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.Hex
import java.security.MessageDigest

/** `reason`: `license-shape`, `bad-alg`, `unknown-key` or `bad-signature`. */
class LicenseException(val reason: String) : Exception(reason)

/** Dates are ISO `YYYY-MM-DD`. */
data class LicenseInfo(
    val licenseId: String,
    val edition: String,
    val name: String,
    val email: String,
    val issuedAt: String,
    val updatesUntil: String,
)

/** Licence bundle verification (desktop `licensing.verify_bundle`, `newer_format`, `sync_state_id`). */
object License {
    const val ID_PREFIX = "lic:"
    private val bundleFields = setOf("license", "signature")
    private val licenseFields = setOf("format", "license_id", "edition", "name", "email", "issued_at", "updates_until")
    private val signatureFields = setOf("alg", "key_id", "signature")

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    /** `"lic:"` + the first 32 lowercase hex digits of SHA-256 of the UTF-8 licence id. */
    fun stateId(licenseId: String): String = ID_PREFIX + Hex.lower(sha256(licenseId.toByteArray(Charsets.UTF_8))).take(32)

    /** [keys]: key id -> raw 32-byte Ed25519 public key. */
    fun verify(bundle: JsonValue, keys: Map<String, ByteArray>): LicenseInfo {
        val b = (bundle as? JsonValue.Obj)?.fields
        if (b == null || b.keys != bundleFields) throw LicenseException("license-shape")
        val lic = (b["license"] as? JsonValue.Obj)?.fields
        if (lic == null || lic.keys != licenseFields) throw LicenseException("license-shape")
        val sig = (b["signature"] as? JsonValue.Obj)?.fields
        if (sig == null || sig.keys != signatureFields) throw LicenseException("license-shape")
        checkSignature(lic, sig, keys)
        // Python: `format != 1` (so 1.0 passes) and not a bool.
        val fmt = lic["format"]
        val formatOk = fmt == JsonValue.Int(1) || fmt == JsonValue.Float(1.0)
        if (!formatOk || lic["edition"] != JsonValue.Str("pro")) throw LicenseException("license-shape")
        val text = HashMap<String, String>()
        for (f in listOf("license_id", "name", "email")) {
            val s = (lic[f] as? JsonValue.Str)?.v
            if (s.isNullOrEmpty()) throw LicenseException("license-shape")
            text[f] = s
        }
        return LicenseInfo(
            text.getValue("license_id"), "pro", text.getValue("name"), text.getValue("email"),
            date(lic["issued_at"]), date(lic["updates_until"]),
        )
    }

    /** True for a correctly signed bundle whose licence `format` is an int above 1. */
    fun newerFormat(bundle: JsonValue, keys: Map<String, ByteArray>): Boolean {
        val b = (bundle as? JsonValue.Obj)?.fields ?: return false
        if (b.keys != bundleFields) return false
        val lic = (b["license"] as? JsonValue.Obj)?.fields ?: return false
        val sig = (b["signature"] as? JsonValue.Obj)?.fields ?: return false
        if (sig.keys != signatureFields) return false
        val fmt = (lic["format"] as? JsonValue.Int)?.v ?: return false
        if (fmt <= 1) return false
        return try {
            checkSignature(lic, sig, keys)
            true
        } catch (e: LicenseException) {
            false
        }
    }

    private fun isLowerHexByte(c: Int): Boolean = (c in 0x30..0x39) || (c in 0x61..0x66)

    private fun checkSignature(lic: Map<String, JsonValue>, sig: Map<String, JsonValue>, keys: Map<String, ByteArray>) {
        if (sig["alg"] != JsonValue.Str("Ed25519")) throw LicenseException("bad-alg")
        val keyId = (sig["key_id"] as? JsonValue.Str)?.v
        val keyBytes = keyId?.toByteArray(Charsets.UTF_8)
        if (keyId == null || keyBytes == null || keyBytes.size != 16 || !keyBytes.all { isLowerHexByte(it.toInt() and 0xFF) }) {
            throw LicenseException("license-shape")
        }
        val raw = keys[keyId]
        if (raw == null || raw.size != 32 || Hex.lower(sha256(raw).copyOf(8)) != keyId) throw LicenseException("unknown-key")
        val encoded = (sig["signature"] as? JsonValue.Str)?.v ?: throw LicenseException("bad-signature")
        val rawSig = try {
            Base64Std.decodeStrict(encoded)
        } catch (e: Base64Exception) {
            throw LicenseException("bad-signature")
        }
        if (rawSig.size != 64) throw LicenseException("bad-signature")
        val message = try {
            CanonicalJson.encode(JsonValue.Obj(lic), Dialect.UTF8)
        } catch (e: JsonException) {
            throw LicenseException("bad-signature")
        }
        if (!Ed25519.verify(rawSig, message, raw)) throw LicenseException("bad-signature")
    }

    private fun date(v: JsonValue?): String {
        val s = (v as? JsonValue.Str)?.v ?: throw LicenseException("license-shape")
        val u = s.toByteArray(Charsets.UTF_8)
        if (u.size != 10) throw LicenseException("license-shape")
        fun digit(i: Int) = (u[i].toInt() and 0xFF) in 0x30..0x39
        if (!listOf(0, 1, 2, 3, 5, 6, 8, 9).all { digit(it) } || u[4].toInt() != 0x2D || u[7].toInt() != 0x2D) {
            throw LicenseException("license-shape")
        }
        val y = s.substring(0, 4).toInt()
        val m = s.substring(5, 7).toInt()
        val d = s.substring(8, 10).toInt()
        if (y < 1 || m !in 1..12) throw LicenseException("license-shape")
        val leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
        val days = intArrayOf(31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[m - 1]
        if (d !in 1..days) throw LicenseException("license-shape")
        return s
    }
}
