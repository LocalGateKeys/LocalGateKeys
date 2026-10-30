package app.localgatekeys.android.passkey

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import java.security.MessageDigest

/** A request the provider cannot serve; the message is fixed text, never request data. */
class WebAuthnException(val reason: Reason) : Exception(reason.name) {
    enum class Reason { MALFORMED, NO_ES256, ORIGIN_REFUSED, RP_ID_REFUSED, EXCLUDED, NOT_FOUND, NEEDS_PRO, PASSKEYS_OFF, STORE_BUSY }
}

private const val MAX_ID = 1023
private const val MAX_CHALLENGE = 4096
private const val MAX_USER_HANDLE = 64

private fun parseObj(json: String): Map<String, JsonValue> = try {
    (CanonicalJson.parse(json.toByteArray(Charsets.UTF_8)) as JsonValue.Obj).fields
} catch (e: Exception) {
    throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
}

private fun str(v: JsonValue?): String? = (v as? JsonValue.Str)?.v

private fun b64(v: JsonValue?, max: Int): ByteArray? = str(v)?.let { Base64Url.decodeLenient(it, max) }

private fun credentialIds(v: JsonValue?): List<ByteArray> = (v as? JsonValue.Arr)?.items?.mapNotNull { c ->
    val f = (c as? JsonValue.Obj)?.fields ?: return@mapNotNull null
    if (f["type"] != null && f["type"] != JsonValue.Str("public-key")) return@mapNotNull null
    b64(f["id"], MAX_ID)?.takeIf { it.isNotEmpty() }
} ?: emptyList()

/** `PublicKeyCredentialCreationOptionsJSON`, reduced to what the authenticator uses. [rpId] null = the caller's host. */
data class CreationRequest(
    val rpId: String?,
    val rpName: String,
    val userHandle: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val challenge: ByteArray,
    val exclude: List<ByteArray>,
) {
    override fun equals(other: Any?): Boolean = other is CreationRequest && rpId == other.rpId && rpName == other.rpName &&
        userHandle.contentEquals(other.userHandle) && userName == other.userName && challenge.contentEquals(other.challenge)

    override fun hashCode(): Int = (rpId ?: "").hashCode() * 31 + userName.hashCode()

    override fun toString(): String = "CreationRequest(rpId=$rpId, exclude=${exclude.size})"

    companion object {
        /** ES256 (COSE -7) must be among `pubKeyCredParams` (an empty list means the WebAuthn defaults, which include it). */
        fun parse(json: String): CreationRequest {
            val f = parseObj(json)
            val rp = (f["rp"] as? JsonValue.Obj)?.fields ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
            val user = (f["user"] as? JsonValue.Obj)?.fields ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
            val handle = b64(user["id"], MAX_USER_HANDLE)?.takeIf { it.isNotEmpty() } ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
            val challenge = b64(f["challenge"], MAX_CHALLENGE)?.takeIf { it.isNotEmpty() } ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
            val params = (f["pubKeyCredParams"] as? JsonValue.Arr)?.items ?: emptyList()
            val es256 = params.isEmpty() || params.any { p ->
                val pf = (p as? JsonValue.Obj)?.fields
                pf?.get("alg") == JsonValue.Int(-7L) && (pf["type"] == null || pf["type"] == JsonValue.Str("public-key"))
            }
            if (!es256) throw WebAuthnException(WebAuthnException.Reason.NO_ES256)
            return CreationRequest(
                rpId = str(rp["id"])?.takeIf { it.isNotEmpty() },
                rpName = str(rp["name"]) ?: "",
                userHandle = handle,
                userName = str(user["name"]) ?: "",
                userDisplayName = str(user["displayName"]) ?: "",
                challenge = challenge,
                exclude = credentialIds(f["excludeCredentials"]),
            )
        }
    }
}

/** `PublicKeyCredentialRequestOptionsJSON`. An empty [allowed] list is a discoverable sign-in. */
data class AssertionRequest(val rpId: String?, val challenge: ByteArray, val allowed: List<ByteArray>) {
    override fun equals(other: Any?): Boolean =
        other is AssertionRequest && rpId == other.rpId && challenge.contentEquals(other.challenge) && allowed.size == other.allowed.size

    override fun hashCode(): Int = (rpId ?: "").hashCode()

    override fun toString(): String = "AssertionRequest(rpId=$rpId, allowed=${allowed.size})"

    companion object {
        fun parse(json: String): AssertionRequest {
            val f = parseObj(json)
            val challenge = b64(f["challenge"], MAX_CHALLENGE)?.takeIf { it.isNotEmpty() } ?: throw WebAuthnException(WebAuthnException.Reason.MALFORMED)
            return AssertionRequest(str(f["rpId"])?.takeIf { it.isNotEmpty() }, challenge, credentialIds(f["allowCredentials"]))
        }
    }
}

/** `CollectedClientData` serialised as browsers do (WebAuthn section 5.8.1.1 member order). */
object ClientData {
    const val CREATE = "webauthn.create"
    const val GET = "webauthn.get"

    /** WebAuthn `CCDToString`: `"` and `\` escaped, controls as `\uXXXX`, everything else verbatim. */
    fun quote(s: String): String {
        val out = StringBuilder("\"")
        for (ch in s) {
            when {
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch.code < 0x20 -> out.append("\\u").append(String.format("%04x", ch.code))
                else -> out.append(ch)
            }
        }
        return out.append('"').toString()
    }

    /** `{"type":..,"challenge":..,"origin":..,"crossOrigin":false[,"androidPackageName":..]}` as UTF-8. */
    fun json(type: String, challenge: ByteArray, origin: String, androidPackageName: String? = null): ByteArray {
        val sb = StringBuilder("{\"type\":").append(quote(type))
            .append(",\"challenge\":").append(quote(Base64Url.encodeNoPad(challenge)))
            .append(",\"origin\":").append(quote(origin))
            .append(",\"crossOrigin\":false")
        if (androidPackageName != null) sb.append(",\"androidPackageName\":").append(quote(androidPackageName))
        return sb.append('}').toString().toByteArray(Charsets.UTF_8)
    }

    fun hash(clientDataJson: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(clientDataJson)

    /** The origin of an app caller: `android:apk-key-hash:<base64url sha256 of the signing certificate>`. */
    fun apkKeyHashOrigin(certSha256: ByteArray): String = "android:apk-key-hash:" + Base64Url.encodeNoPad(certSha256)
}

/** Registration and assertion response JSON (`RegistrationResponseJSON`, `AuthenticationResponseJSON`). */
object WebAuthnResponse {
    /** Sent when the browser built clientDataJSON itself (it supplied the hash and replaces this field): `{}`. */
    val PLACEHOLDER_CLIENT_DATA: ByteArray = "{}".toByteArray(Charsets.UTF_8)

    private fun s(v: String): JsonValue = JsonValue.Str(v)
    private fun b(v: ByteArray): JsonValue = JsonValue.Str(Base64Url.encodeNoPad(v))

    private fun text(v: JsonValue): String = CanonicalJson.encode(v, Dialect.UTF8).toString(Charsets.UTF_8)

    fun registration(credentialId: ByteArray, clientDataJson: ByteArray, attestationObject: ByteArray, authData: ByteArray, spki: ByteArray): String =
        text(
            JsonValue.Obj(
                mapOf(
                    "id" to b(credentialId), "rawId" to b(credentialId), "type" to s("public-key"),
                    "authenticatorAttachment" to s("platform"),
                    "response" to JsonValue.Obj(
                        mapOf(
                            "clientDataJSON" to b(clientDataJson), "attestationObject" to b(attestationObject),
                            "authenticatorData" to b(authData), "transports" to JsonValue.Arr(listOf(s("hybrid"), s("internal"))),
                            "publicKey" to b(spki), "publicKeyAlgorithm" to JsonValue.Int(-7),
                        ),
                    ),
                    "clientExtensionResults" to JsonValue.Obj(mapOf("credProps" to JsonValue.Obj(mapOf("rk" to JsonValue.Bool(true))))),
                ),
            ),
        )

    fun assertion(credentialId: ByteArray, clientDataJson: ByteArray, authData: ByteArray, signature: ByteArray, userHandle: ByteArray): String =
        text(
            JsonValue.Obj(
                mapOf(
                    "id" to b(credentialId), "rawId" to b(credentialId), "type" to s("public-key"),
                    "authenticatorAttachment" to s("platform"),
                    "response" to JsonValue.Obj(
                        mapOf(
                            "clientDataJSON" to b(clientDataJson), "authenticatorData" to b(authData),
                            "signature" to b(signature), "userHandle" to b(userHandle),
                        ),
                    ),
                    "clientExtensionResults" to JsonValue.Obj(emptyMap()),
                ),
            ),
        )
}
