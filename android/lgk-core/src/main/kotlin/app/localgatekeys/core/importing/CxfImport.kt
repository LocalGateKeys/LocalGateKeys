package app.localgatekeys.core.importing

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.primitives.Base64Url
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.time.Instant
import java.time.ZoneOffset

/**
 * Credential Exchange Format (CXF v1.0) account exports: one `Account` JSON (the file Apple Passwords and other
 * providers write) whose `items` hold typed credentials. Port of the Windows `importers/cxf.py`, the same mapping as
 * the iPhone, Mac and Windows apps:
 *
 * * `basic-auth` -> a login (`scope.urls`, username, password); one per item, a second one is counted as skipped;
 * * `totp` -> the login of the same item as an `otpauth://` URI; a code with no login becomes a login holding only the
 *   code, which the review keeps as a secure note with the code (a login needs a password);
 * * `note` -> the login's notes, or a secure note when the item has no login and no code;
 * * `passkey` -> a [ImportCandidate.Kind.PASSKEY] candidate whose [ImportCandidate.passkey] holds the vault payload
 *   (the private key as base64url PKCS#8 DER);
 * * any other credential type is skipped and named, never dropped silently. Unknown fields are ignored.
 *
 * The file is untrusted: it is read with the 8 MiB import cap and any malformed value is skipped rather than raised.
 */
object CxfImport {
    /** The vault passkey payload keys an imported passkey carries, in the desktop's order. */
    val PASSKEY_KEYS = listOf(
        "relying_party_id", "user_handle", "credential_id", "private_key", "algorithm", "user_name", "user_display_name", "created",
    )

    /** [ImportSkip.code] of the skipped-types line; [ImportSkip.args] are the count and the "name (n)" list. */
    const val SKIPPED_TYPES = "cxf.skippedTypes"

    const val NOT_A_CXF_EXPORT = "This file is not a Credential Exchange (CXF) export."

    private const val MAX_CREDENTIAL_ID = 1023
    private const val MAX_USER_HANDLE = 64
    private const val MAX_KEY_BYTES = 4096
    private const val MAX_TEXT = 4096
    private const val LAST_DAY = 253402300800L
    private val ED25519 = ASN1ObjectIdentifier("1.3.101.112")

    /** A CXF account: an `items` list whose entries carry `credentials` objects with a `type` (Windows `_is_cxf`). */
    internal fun isAccount(doc: PyJson): Boolean {
        val items = doc["items"] as? PyJson.Arr ?: return false
        for (item in items.items.take(50)) {
            val credentials = (if (item.isObject) item["credentials"] else null) as? PyJson.Arr ?: continue
            if (credentials.items.take(20).any { it.isObject && it["type"] is PyJson.Str }) return true
        }
        return false
    }

    fun candidates(data: ByteArray): ImportResult {
        val (candidates, skipped) = parse(data)
        if (skipped.isEmpty()) return ImportResult(candidates)
        val counts = java.util.TreeMap<String, Int>()
        for (name in skipped) counts[name] = (counts[name] ?: 0) + 1
        val names = counts.entries.joinToString(", ") { "${it.key} (${it.value})" }
        val line = ImportSkip(
            message = "Skipped ${skipped.size} credentials of types LocalGateKeys cannot store: $names.",
            code = SKIPPED_TYPES, args = listOf(skipped.size.toString(), names),
        )
        return ImportResult(candidates, listOf(line))
    }

    /** The candidates and the names of the skipped credential types (Windows `parse_cxf`). */
    internal fun parse(data: ByteArray): Pair<List<ImportCandidate>, List<String>> {
        val bytes = ImportText.bounded(data)
        val start = if (bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()) 3 else 0
        val text = try {
            Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes, start, bytes.size - start)).toString()
        } catch (e: CharacterCodingException) {
            throw ImportException.malformed(NOT_A_CXF_EXPORT)
        }
        val doc = try {
            PyJson.parse(text)
        } catch (e: Exception) {
            throw ImportException.malformed(NOT_A_CXF_EXPORT)
        }
        val items = (if (doc.isObject) doc["items"] else null) as? PyJson.Arr ?: throw ImportException.malformed(NOT_A_CXF_EXPORT)
        val out = ArrayList<ImportCandidate>()
        val skipped = ArrayList<String>()
        for (item in items.items) {
            if (!item.isObject) continue
            out.addAll(mapItem(item, skipped))
            if (out.size > ImportSource.MAX_RECORDS) throw ImportException(ImportException.Kind.TOO_MANY_ROWS)
        }
        return out to skipped
    }

    /** An EditableField (`{"value": ...}`) or a bare string, at most [limit] characters; anything else is "". */
    private fun text(value: PyJson?, limit: Int = MAX_TEXT): String {
        val v = if (value != null && value.isObject) value["value"] else value
        return if (v is PyJson.Str) Py.prefix(v.v, limit) else ""
    }

    /** Base64url or standard base64, padded or not; null when invalid or longer than [maxBytes]. */
    private fun b64(value: PyJson?, maxBytes: Int): ByteArray? {
        val s = (value as? PyJson.Str)?.v ?: return null
        if (s.codePointCount(0, s.length) > (maxBytes * 4) / 3 + 4) return null
        val body = Py.strip(s).replace('+', '-').replace('/', '_').trimEnd('=')
        return Base64Url.decodeLenient(body, maxBytes)
    }

    private fun int(value: PyJson?, default: Int, low: Int, high: Int): Int {
        val v = (value as? PyJson.Int)?.v ?: return default
        return if (v in low..high) v.toInt() else default
    }

    /** Windows `totp_uri_from_secret`: an `otpauth://totp` URI for a bare Base32 secret (an URI is returned as is). */
    fun totpUri(secret: String, label: String = "", issuer: String = "", digits: Int = 6, period: Int = 30, algorithm: String = "SHA1"): String {
        val value = Py.strip(secret)
        if (value.isEmpty()) return ""
        if (Py.casefold(value).startsWith("otpauth://")) return value
        val compact = Py.split(value.replace("-", "")).joinToString("").uppercase().trimEnd('=')
        if (compact.isEmpty()) return ""
        val query = arrayListOf("secret=$compact")
        if (issuer.isNotEmpty()) query.add("issuer=${Py.quote(issuer, "")}")
        if (digits != 6) query.add("digits=$digits")
        if (period != 30) query.add("period=$period")
        val alg = algorithm.ifEmpty { "SHA1" }.uppercase().replace("HMAC-", "").replace("-", "")
        if (alg != "SHA1") query.add("algorithm=$alg")
        return "otpauth://totp/${Py.quote(label.ifEmpty { "account" }, "@:")}?" + query.joinToString("&")
    }

    private fun otpauth(credential: PyJson, fallbackUsername: String): String {
        val secret = text(credential["secret"], 1024)
        if (secret.isEmpty()) return ""
        val raw = (credential["algorithm"] as? PyJson.Str)?.v?.uppercase()
        val algorithm = if (raw != null && raw in setOf("SHA1", "SHA256", "SHA512")) raw else "SHA1"
        val issuer = text(credential["issuer"], 256)
        val username = text(credential["username"], 256).ifEmpty { fallbackUsername }
        val label = if (issuer.isNotEmpty() && username.isNotEmpty()) "$issuer:$username" else username.ifEmpty { issuer }
        return totpUri(
            secret, label = label, issuer = issuer, digits = int(credential["digits"], 6, 6, 8),
            period = int(credential["period"], 30, 1, 86400), algorithm = algorithm,
        )
    }

    /**
     * The COSE algorithm name of a PKCS#8 DER private key (ES256/384/512, EdDSA, RS256), or null when it is not one of
     * those or does not parse. An ES256 key must also be one the phone can sign with ([PasskeyKey]).
     */
    internal fun algorithm(der: ByteArray): String? = try {
        val info = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der))
        val oid = info.privateKeyAlgorithm.algorithm
        val params = PrivateKeyFactory.createKey(info)
        when {
            oid == X9ObjectIdentifiers.id_ecPublicKey -> {
                val curve = ASN1ObjectIdentifier.getInstance(info.privateKeyAlgorithm.parameters)
                val ec = params as ECPrivateKeyParameters
                val d = ec.d
                if (d.signum() <= 0 || d >= ec.parameters.n) {
                    null
                } else when (curve) {
                    X9ObjectIdentifiers.prime256v1 -> if (PasskeyKey.fromPkcs8B64Url(Base64Url.encodeNoPad(der)) != null) "ES256" else null
                    SECObjectIdentifiers.secp384r1 -> "ES384"
                    SECObjectIdentifiers.secp521r1 -> "ES512"
                    else -> null
                }
            }
            oid == ED25519 -> "EdDSA"
            oid == PKCSObjectIdentifiers.rsaEncryption -> "RS256"
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    private fun created(item: PyJson): String {
        val stamp = (item["creationAt"] as? PyJson.Int)?.v ?: return ""
        if (stamp <= 0 || stamp >= LAST_DAY) return ""
        return Instant.ofEpochSecond(stamp).atOffset(ZoneOffset.UTC).toLocalDate().toString()
    }

    private fun passkey(credential: PyJson, title: String, urls: List<String>, item: PyJson): ImportCandidate? {
        val credentialId = b64(credential["credentialId"], MAX_CREDENTIAL_ID)
        val rpId = Py.casefold(Py.strip(text(credential["rpId"], 253)))
        val der = b64(credential["key"], MAX_KEY_BYTES)
        try {
            if (credentialId == null || credentialId.isEmpty() || rpId.isEmpty() || der == null || der.isEmpty()) return null
            val algorithm = algorithm(der) ?: return null
            val handle = credential["userHandle"]
            var userHandle = ByteArray(0)
            if (handle != null && handle != PyJson.Null && handle != PyJson.Str("")) userHandle = b64(handle, MAX_USER_HANDLE) ?: return null
            val userName = text(credential["username"], 256).ifEmpty { text(credential["userName"], 256) }
            val values = mapOf(
                "relying_party_id" to rpId, "user_handle" to Base64Url.encodeNoPad(userHandle),
                "credential_id" to Base64Url.encodeNoPad(credentialId), "private_key" to Base64Url.encodeNoPad(der),
                "algorithm" to algorithm, "user_name" to userName, "user_display_name" to text(credential["userDisplayName"], 256),
                "created" to created(item),
            )
            val payload = LinkedHashMap<String, String>()
            for (key in PASSKEY_KEYS) values[key]?.takeIf { it.isNotEmpty() }?.let { payload[key] = it }
            return ImportCandidate(
                kind = ImportCandidate.Kind.PASSKEY, title = title.ifEmpty { rpId }, username = userName,
                urls = urls.ifEmpty { listOf("https://$rpId") }, passkey = payload,
            )
        } finally {
            der?.fill(0)
        }
    }

    private fun mapItem(item: PyJson, skipped: MutableList<String>): List<ImportCandidate> {
        val title = text(item["title"], 512)
        val scope = item["scope"]
        val rawUrls = (if (scope != null && scope.isObject) scope["urls"] else null) as? PyJson.Arr
        val urls = rawUrls?.items?.mapNotNull { (it as? PyJson.Str)?.v?.takeIf { u -> u.isNotEmpty() } }?.take(50) ?: emptyList()
        val credentials = item["credentials"] as? PyJson.Arr ?: return emptyList()
        val logins = ArrayList<PyJson>()
        val totps = ArrayList<PyJson>()
        val notes = ArrayList<String>()
        val out = ArrayList<ImportCandidate>()
        for (credential in credentials.items) {
            val kind = (if (credential.isObject) credential["type"] else null) as? PyJson.Str
            if (kind == null) { skipped.add("unknown"); continue }
            when (kind.v) {
                // One login per item, as on the iPhone and the Mac.
                "basic-auth" -> if (logins.isNotEmpty()) skipped.add(kind.v) else logins.add(credential)
                "totp" -> totps.add(credential)
                "note" -> text(credential["content"], 64 * 1024).takeIf { it.isNotEmpty() }?.let { notes.add(it) }
                "passkey" -> passkey(credential, title, urls, item)?.let { out.add(it) } ?: skipped.add("passkey")
                else -> skipped.add(Py.prefix(kind.v, 64).ifEmpty { "unknown" })
            }
        }
        val noteText = notes.joinToString("\n\n")
        val stamp = (item["creationAt"] as? PyJson.Int)?.v?.takeIf { created(item).isNotEmpty() }
        val loginSources: List<PyJson?> = if (logins.isNotEmpty()) logins else if (totps.isNotEmpty()) listOf(null) else emptyList()
        for ((index, credential) in loginSources.withIndex()) {
            val username = if (credential == null) "" else text(credential["username"], 512)
            val totp = if (index < totps.size) otpauth(totps[index], username) else ""
            out.add(
                ImportCandidate(
                    kind = ImportCandidate.Kind.LOGIN, title = title, username = username,
                    password = if (credential == null) "" else text(credential["password"]), urls = urls,
                    notes = if (index == 0) noteText else "", totp = totp, created = stamp,
                ),
            )
        }
        for (extra in totps.drop(maxOf(logins.size, 1))) {
            out.add(ImportCandidate(kind = ImportCandidate.Kind.LOGIN, title = title, urls = urls, totp = otpauth(extra, "")))
        }
        if (noteText.isNotEmpty() && logins.isEmpty() && totps.isEmpty()) {
            out.add(0, ImportCandidate(kind = ImportCandidate.Kind.NOTE, title = title, notes = noteText))
        }
        return out
    }
}
