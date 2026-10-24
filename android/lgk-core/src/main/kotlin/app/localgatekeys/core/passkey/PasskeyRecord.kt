package app.localgatekeys.core.passkey

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Url
import app.localgatekeys.core.primitives.Casefold
import app.localgatekeys.core.records.PyStrip

/** The item title and payload fields [PasskeyRecord.newPayload] returns. */
data class NewPayload(val title: String, val fields: JsonValue)

/**
 * A stored passkey item, read from a snapshot item (the sync wrapper `{"ns", ..., "record"}` or a bare
 * record). Reading never rewrites the item. Port of Swift `PasskeyRecord`.
 *
 * [key] is null when the record is not usable for sign-in (desktop `passkeys.usable_record`: ES256, a non-empty
 * credential id of at most 1023 bytes, and a P-256 PKCS#8 private key). Equality compares the byte arrays by
 * content; [toString] prints no key material.
 */
data class PasskeyRecord(
    val itemId: String,
    val title: String,
    val rpId: String,
    val userName: String,
    val userHandle: ByteArray,
    val credentialId: ByteArray,
    val key: PasskeyKey?,
) {
    override fun equals(other: Any?): Boolean =
        other is PasskeyRecord && itemId == other.itemId && title == other.title && rpId == other.rpId &&
            userName == other.userName && userHandle.contentEquals(other.userHandle) &&
            credentialId.contentEquals(other.credentialId) && key == other.key

    override fun hashCode(): Int {
        var h = itemId.hashCode()
        h = 31 * h + title.hashCode()
        h = 31 * h + rpId.hashCode()
        h = 31 * h + userName.hashCode()
        h = 31 * h + userHandle.contentHashCode()
        h = 31 * h + credentialId.contentHashCode()
        h = 31 * h + (key?.hashCode() ?: 0)
        return h
    }

    /** No user handle, credential id or key bytes. */
    override fun toString(): String =
        "PasskeyRecord(itemId=$itemId, title=$title, rpId=$rpId, userName=$userName, usable=${key != null})"

    companion object {
        /** desktop `passkeys.MAX_CREDENTIAL_ID` */
        private const val MAX_CREDENTIAL_ID = 1023

        /** The stored form of a relying party id (stripped, casefolded), for matching what the phone passes. */
        fun normaliseRpId(rpId: String): String = Casefold.fold(PyStrip.strip(rpId))

        private fun text(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""

        /** null for anything that is not a `passkey` item. */
        fun from(snapshotItem: JsonValue, id: String): PasskeyRecord? {
            var rec = (snapshotItem as? JsonValue.Obj)?.fields ?: return null
            (rec["record"] as? JsonValue.Obj)?.let { rec = it.fields }
            if (rec["kind"] != JsonValue.Str("passkey")) return null
            val p = (rec["payload"] as? JsonValue.Obj)?.fields ?: return null
            val credText = PyStrip.strip(text(p["credential_id"]))
            val credentialId = Base64Url.decodeLenient(credText, MAX_CREDENTIAL_ID) ?: ByteArray(0)
            var key: PasskeyKey? = null
            val k = p["private_key"]
            if (p["algorithm"] == JsonValue.Str("ES256") && credentialId.isNotEmpty() && k is JsonValue.Str) {
                key = PasskeyKey.fromPkcs8B64Url(k.v)
            }
            return PasskeyRecord(
                itemId = id,
                title = text(rec["title"]),
                rpId = normaliseRpId(text(p["relying_party_id"])),
                userName = text(p["user_name"]),
                userHandle = Base64Url.decodeLenient(PyStrip.strip(text(p["user_handle"])), 1024) ?: ByteArray(0),
                credentialId = credentialId,
                key = key,
            )
        }

        /**
         * The item title and payload desktop `passkeys.create_credential` writes, plus the normaliser defaults
         * (`notes`, `template_id`) so the payload is its own normal form. [today] is `YYYY-MM-DD`.
         */
        fun newPayload(
            rpId: String,
            rpName: String,
            userName: String,
            userDisplayName: String,
            userHandle: ByteArray,
            credentialId: ByteArray,
            key: PasskeyKey,
            today: String,
        ): NewPayload {
            val rp = normaliseRpId(rpId)
            var title = rpName.ifEmpty { rp }
            if (userName.isNotEmpty()) title += " ($userName)"
            fun s(v: String): JsonValue = JsonValue.Str(v)
            val fields = JsonValue.Obj(
                linkedMapOf(
                    "relying_party_id" to s(rp),
                    "rp_name" to s(rpName),
                    "user_handle" to s(Base64Url.encodeNoPad(userHandle)),
                    "user_name" to s(userName),
                    "user_display_name" to s(userDisplayName),
                    "credential_id" to s(Base64Url.encodeNoPad(credentialId)),
                    "private_key" to s(key.pkcs8B64Url),
                    "algorithm" to s("ES256"),
                    "created" to s(today),
                    "discoverable" to JsonValue.Bool(true),
                    "notes" to s(""),
                    "template_id" to JsonValue.Null,
                ),
            )
            return NewPayload(title, fields)
        }
    }
}
