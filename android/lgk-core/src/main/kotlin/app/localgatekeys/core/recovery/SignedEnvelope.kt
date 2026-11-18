package app.localgatekeys.core.recovery

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Exception
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.records.PyStrip

/** `reason`: `malformed`, `unsupported` (another version) or `bad-signature` (desktop `envelope.EnvelopeError`). */
class EnvelopeException(val reason: String) : Exception(reason)

/** One verified signed envelope: the signer's public key and the parsed, canonical payload. */
class SignedEnvelope(
    val format: String,
    val version: Long,
    val id: String,
    val sender: String,
    signer: ByteArray,
    val payload: Map<String, JsonValue>,
) {
    private val signerBytes = signer.copyOf()
    val signer: ByteArray get() = signerBytes.copyOf()
}

/**
 * The signed envelope of `.lgkheir` and the heir folder files: port of `src/localvault/envelope.py` (byte rules in
 * `docs/formats/LGKHEIR_V1.md`). One canonical JSON object `{format, version, id, sender, signer, payload, sig}`;
 * `payload` is base64 of the payload's exact canonical bytes; the Ed25519 signature covers [SIGN_CONTEXT] followed by
 * the canonical JSON of every field but `sig`. The signature is checked before the payload is parsed.
 */
object Envelope {
    val SIGN_CONTEXT: ByteArray = "LocalGateKeys signed envelope v1\n".toByteArray(Charsets.US_ASCII)
    const val SENDER_LIMIT = 64
    private val SIGNED_FIELDS = listOf("format", "version", "id", "sender", "signer", "payload")
    private val UUID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

    /** Sorted keys (by code point), no spaces, UTF-8 (desktop `canonical`). */
    fun canonical(value: JsonValue): ByteArray = CanonicalJson.encode(value, Dialect.UTF8)

    fun b64e(value: ByteArray): String = Base64Std.encode(value)

    /** Strict standard base64 (padding required, exact round trip); [size] pins the decoded length. */
    fun b64d(value: JsonValue?, size: Int? = null): ByteArray {
        val s = (value as? JsonValue.Str)?.v ?: throw EnvelopeException("malformed")
        val out = try {
            Base64Std.decodeStrict(s)
        } catch (e: Base64Exception) {
            throw EnvelopeException("malformed")
        }
        if (size != null && out.size != size) throw EnvelopeException("malformed")
        return out
    }

    /** At most [limit] bytes of UTF-8 JSON that must be an object (duplicate keys refused). */
    fun loadObject(data: ByteArray, limit: Int): Map<String, JsonValue> {
        if (data.size > limit) throw EnvelopeException("malformed")
        val value = try {
            CanonicalJson.parse(data)
        } catch (e: JsonException) {
            throw EnvelopeException("malformed")
        } catch (e: RuntimeException) {
            throw EnvelopeException("malformed")
        }
        return (value as? JsonValue.Obj)?.fields ?: throw EnvelopeException("malformed")
    }

    /** A lower-case canonical UUID string, else `malformed`. */
    fun checkedId(value: JsonValue?): String {
        val s = (value as? JsonValue.Str)?.v ?: throw EnvelopeException("malformed")
        if (!isId(s)) throw EnvelopeException("malformed")
        return s
    }

    fun isId(s: String): Boolean = UUID.matches(s)

    /** Python `len(str)`: code points. */
    internal fun length(s: String): Int = s.codePointCount(0, s.length)

    private fun message(header: Map<String, JsonValue>): ByteArray =
        SIGN_CONTEXT + canonical(JsonValue.Obj(SIGNED_FIELDS.associateWith { header.getValue(it) }))

    /** The canonical bytes of one signed envelope, signed with the Ed25519 [seed]. */
    fun seal(
        format: String,
        version: Long,
        packageId: String,
        sender: String,
        payload: Map<String, JsonValue>,
        seed: ByteArray,
    ): ByteArray {
        val name = PyStrip.strip(sender)
        if (length(name) > SENDER_LIMIT) throw EnvelopeException("malformed")
        if (!isId(packageId)) throw EnvelopeException("malformed")
        val header = linkedMapOf<String, JsonValue>(
            "format" to JsonValue.Str(format),
            "version" to JsonValue.Int(version),
            "id" to JsonValue.Str(packageId),
            "sender" to JsonValue.Str(name),
            "signer" to JsonValue.Str(b64e(Ed25519.publicKey(seed))),
            "payload" to JsonValue.Str(b64e(canonical(JsonValue.Obj(payload)))),
        )
        header["sig"] = JsonValue.Str(b64e(Ed25519.sign(seed, message(header))))
        return canonical(JsonValue.Obj(header))
    }

    /** Parses and verifies one signed envelope (signature first, then the payload must be canonical). */
    fun open(data: ByteArray, format: String, version: Long, limit: Int): SignedEnvelope {
        val outer = loadObject(data, limit)
        if (outer["format"] != JsonValue.Str(format)) throw EnvelopeException("malformed")
        if (outer["version"] != JsonValue.Int(version)) throw EnvelopeException("unsupported")
        if (outer.keys != (SIGNED_FIELDS + "sig").toSet()) throw EnvelopeException("malformed")
        val id = checkedId(outer["id"])
        val sender = (outer["sender"] as? JsonValue.Str)?.v ?: throw EnvelopeException("malformed")
        if (length(sender) > SENDER_LIMIT) throw EnvelopeException("malformed")
        val signer = b64d(outer["signer"], 32)
        val signature = b64d(outer["sig"], 64)
        val rawPayload = b64d(outer["payload"])
        if (!Ed25519.verify(signature, message(outer), signer)) throw EnvelopeException("bad-signature")
        val payload = loadObject(rawPayload, limit)
        if (!canonical(JsonValue.Obj(payload)).contentEquals(rawPayload)) throw EnvelopeException("malformed")
        return SignedEnvelope(format, version, id, sender, signer, payload)
    }
}
