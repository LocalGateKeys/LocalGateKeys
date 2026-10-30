package app.localgatekeys.core.importing

import app.localgatekeys.core.crypto.Argon2
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Bitwarden exports: unencrypted JSON and CSV; the password-protected JSON is opened by [BitwardenEncrypted]. */
internal object BitwardenJson {
    const val ACCOUNT_RESTRICTED_MESSAGE =
        "This Bitwarden export is encrypted with your Bitwarden account key, so only Bitwarden can open it. " +
            "In Bitwarden choose Export vault, then either File format 'JSON' (unencrypted) or " +
            "'.json (Encrypted)' with Export type 'Password protected', and enter that password here."

    private val IDENTITY_MAP = listOf(
        "firstName" to "given_name", "middleName" to "middle_name", "lastName" to "family_name", "company" to "company",
        "email" to "email", "phone" to "phone", "address1" to "address_line1", "address2" to "address_line2", "city" to "city",
        "state" to "state", "postalCode" to "postal_code", "country" to "country",
    )
    private val IDENTITY_SENSITIVE = listOf("ssn" to "SSN", "passportNumber" to "Passport number", "licenseNumber" to "Licence number")
    private val IDENTITY_EXTRA = listOf("title" to "Title", "username" to "Username", "address3" to "Address 3")
    private val SPACE = setOf(0xFEFF, ' '.code, '\t'.code, '\r'.code, '\n'.code)

    fun candidates(data: ByteArray, options: ImportOptions): ImportResult {
        val text = ImportText.text(data)
        if (Py.lstrip(text, SPACE).startsWith("{")) return json(text, options.password)
        return csv(text)
    }

    /** Windows `load_bitwarden_json`. */
    fun json(text: String, password: String?): ImportResult {
        val doc = try {
            PyJson.parse(text)
        } catch (e: Exception) {
            throw ImportException.malformed("Invalid JSON")
        }
        if (!doc.isObject) throw ImportException.malformed("Expected a Bitwarden JSON export object")
        if (doc["encrypted"]?.isTrue == true && doc["passwordProtected"]?.truthy != true) {
            throw ImportException.malformed(ACCOUNT_RESTRICTED_MESSAGE)
        }
        if (doc["encrypted"]?.truthy == true && doc.has("data")) {
            if (doc["passwordProtected"]?.truthy != true) throw ImportException.malformed(ACCOUNT_RESTRICTED_MESSAGE)
            if (password.isNullOrEmpty()) throw ImportException(ImportException.Kind.NEEDS_PASSWORD)
            return records(BitwardenEncrypted.decrypt(doc, password))
        }
        return records(doc)
    }

    /** Windows `records_from_document`. */
    fun records(doc: PyJson): ImportResult {
        val items = (doc["items"] as? PyJson.Arr)?.items
            ?: throw ImportException.malformed("Expected a Bitwarden JSON export with an 'items' list")
        ImportRules.checkCount(items.size)
        val folders = HashMap<String, String>()
        for (key in listOf("folders", "collections")) {
            for (f in doc[key]?.list ?: emptyList()) {
                if (!f.isObject) continue
                val id = f["id"]
                if (id != null && id != PyJson.Null) folders[id.str] = PyJson.text(f["name"])
            }
        }
        val records = ArrayList<ImportRecord>()
        val diagnostics = ArrayList<String>()
        var passkeys = 0
        for ((offset, item) in items.withIndex()) {
            val index = offset + 1
            if (!item.isObject) { diagnostics.add("Item $index: not an object; skipped."); continue }
            if (item["deletedDate"]?.truthy == true) {
                diagnostics.add("Item $index: in the Bitwarden trash; skipped.")
                continue
            }
            val record = itemRecord(item, folders, index) ?: ImportRecord(
                kind = "note", title = PyJson.text(item["name"]), notes = PyJson.text(item["notes"]), row = index,
            ).also {
                it.addField("Bitwarden item type", item["type"])
                customFields(item, it)
                diagnostics.add("Item $index: unknown Bitwarden item type ${(item["type"] ?: PyJson.Null).repr}; imported as a secure note.")
            }
            val login = item["login"]
            if (login != null && login.isObject && login["fido2Credentials"]?.truthy == true) passkeys++
            records.add(record)
        }
        if (passkeys > 0) {
            diagnostics.add(
                "$passkeys login(s) have passkeys; Bitwarden does not export passkeys in a " +
                    "form another manager can use, so only the password was imported.",
            )
        }
        return ImportRules.result(records, diagnostics)
    }

    private fun customFields(item: PyJson, record: ImportRecord) {
        for (field in item["fields"]?.list ?: emptyList()) {
            if (!field.isObject) continue
            val name = PyJson.text(field["name"])
            var value = field["value"] ?: continue
            if (value == PyJson.Null) continue
            val kind = field["type"] ?: PyJson.Int(0)
            if (kind.equalsNumber(3)) continue
            if (kind.equalsNumber(2)) value = PyJson.Str(if (Py.casefold(value.str) == "true") "true" else "false")
            record.addField(name, value, hidden = kind.equalsNumber(1))
        }
    }

    private fun obj(v: PyJson?): PyJson = if (v != null && v.isObject) v else PyJson.Obj(emptyList())

    fun itemRecord(item: PyJson, folders: Map<String, String>, row: Int): ImportRecord? {
        val type = item["type"] ?: PyJson.Null
        val name = PyJson.text(item["name"])
        var folder = ""
        val folderId = item["folderId"]
        if (folderId != null && folderId.truthy) folder = folders[folderId.str] ?: ""
        if (folder.isEmpty()) {
            for (c in item["collectionIds"]?.list ?: emptyList()) {
                folder = folders[c.str] ?: ""
                if (folder.isNotEmpty()) break
            }
        }
        val r = ImportRecord(
            title = name, notes = PyJson.text(item["notes"]), folder = folder, favourite = item["favorite"]?.truthy ?: false,
            created = ImportTime.parse(item["creationDate"]), modified = ImportTime.parse(item["revisionDate"]), row = row,
        )
        when {
            type.equalsNumber(1) -> {
                val login = obj(item["login"])
                r.kind = "login"
                r.username = PyJson.text(login["username"])
                r.password = PyJson.text(login["password"])
                r.urls = (login["uris"]?.list ?: emptyList())
                    .mapNotNull { u -> if (u.isObject && u["uri"]?.truthy == true) u["uri"]!!.str else null }.toMutableList()
                r.totp = ImportRules.totpUri(PyJson.text(login["totp"]), name)
            }
            type.equalsNumber(2) -> r.kind = "note"
            type.equalsNumber(3) -> {
                val card = obj(item["card"])
                r.kind = "card"
                r.card.putAll(
                    ImportRecord.cleanCard(
                        mapOf(
                            "cardholder" to PyJson.scalarText(card["cardholderName"]), "number" to PyJson.scalarText(card["number"]),
                            "cvv" to PyJson.scalarText(card["code"]), "brand" to PyJson.scalarText(card["brand"]),
                        ),
                    ),
                )
                val expiry = ImportRules.cardExpiry(PyJson.scalarText(card["expMonth"]), PyJson.scalarText(card["expYear"]))
                if (expiry.isNotEmpty()) {
                    r.card["expiry"] = expiry
                } else {
                    val raw = listOf("expMonth", "expYear").filter { card[it]?.truthy == true }.map { PyJson.scalarText(card[it]) }
                    r.addField("Expiry", raw.joinToString("/"))
                }
            }
            type.equalsNumber(4) -> {
                val identity = obj(item["identity"])
                r.kind = "identity"
                for ((key, target) in IDENTITY_MAP) if (identity[key]?.truthy == true) r.identity[target] = identity[key]!!.str
                val full = listOf("firstName", "middleName", "lastName").filter { identity[it]?.truthy == true }.map { identity[it]!!.str }
                if (full.isNotEmpty()) r.identity["name"] = full.joinToString(" ")
                for ((key, label) in IDENTITY_EXTRA) r.addField(label, identity[key])
                for ((key, label) in IDENTITY_SENSITIVE) r.addField(label, identity[key], hidden = true)
            }
            type.equalsNumber(5) -> {
                val key = obj(item["sshKey"])
                r.kind = "note"
                r.addField("Bitwarden item type", "SSH key")
                r.addField("Private key", key["privateKey"], hidden = true)
                r.addField("Public key", key["publicKey"])
                r.addField("Fingerprint", key["keyFingerprint"])
            }
            else -> return null
        }
        customFields(item, r)
        return r
    }

    /** Windows `load_bitwarden_csv`. */
    fun csv(text: String): ImportResult {
        val rows = CsvTable.read(text).second
        val records = ArrayList<ImportRecord>()
        val diagnostics = ArrayList<String>()
        for (row in rows) {
            val typed = Py.casefold(row.pick("type"))
            val kind = typed.ifEmpty { "login" }
            val name = row.pick("name")
            val r = ImportRecord(
                kind = "note", title = name, notes = row.pick("notes"), folder = row.pick("folder"),
                favourite = ImportRules.truthy(row.pick("favorite")), row = row.number,
            )
            if (kind == "note") {
                // a secure note
            } else if (kind == "login") {
                r.kind = "login"
                r.username = row.pick("login_username")
                r.password = row.pick("login_password")
                r.urls = row.pick("login_uri").split(',').map { Py.strip(it) }.filter { it.isNotEmpty() }.toMutableList()
                r.totp = ImportRules.totpUri(row.pick("login_totp"), name)
            } else {
                diagnostics.add("Row ${row.number}: unsupported type ${PyJson.Str(kind).repr}; imported as a note.")
            }
            for (line in Py.splitlines(row.pick("fields"))) {
                val (n, v) = Py.partition(line, ':') ?: continue
                r.addField(Py.strip(n), Py.strip(v))
            }
            records.add(r)
        }
        return ImportRules.result(records, diagnostics)
    }
}

/**
 * Bitwarden's password-protected JSON export (Windows `decrypt_bitwarden_export`): `2.` EncStrings, AES-256-CBC with
 * HMAC-SHA256, keys stretched with PBKDF2-SHA256 or Argon2id and expanded with HKDF (`enc`/`mac`).
 */
internal object BitwardenEncrypted {
    const val MAX_PBKDF2_ITERATIONS = 2_000_000
    const val MAX_ARGON2_MEMORY_MIB = 1024
    const val MAX_ARGON2_ITERATIONS = 10
    const val MAX_ARGON2_PARALLELISM = 16

    fun candidates(data: ByteArray, options: ImportOptions): ImportResult {
        val password = options.password
        if (password.isNullOrEmpty()) throw ImportException(ImportException.Kind.NEEDS_PASSWORD)
        return BitwardenJson.json(ImportText.text(data), password)
    }

    fun decrypt(doc: PyJson, password: String): PyJson {
        if (doc["passwordProtected"]?.truthy != true) throw ImportException.malformed(BitwardenJson.ACCOUNT_RESTRICTED_MESSAGE)
        val (encKey, macKey) = keys(password, doc)
        try {
            doc["encKeyValidation_DO_NOT_EDIT"]?.let { open(it, encKey, macKey) }
            val raw = open(doc["data"] ?: PyJson.Null, encKey, macKey)
            val text = try {
                Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(raw)).toString()
            } catch (e: Exception) {
                null
            }
            raw.fill(0)
            val inner = try {
                text?.let { PyJson.parse(it) }
            } catch (e: Exception) {
                null
            } ?: throw ImportException.malformed("Decrypted export is not valid JSON")
            if (!inner.isObject) throw ImportException.malformed("Decrypted export is not a Bitwarden document")
            return inner
        } finally {
            encKey.fill(0); macKey.fill(0)
        }
    }

    /** Python `int(value or default)` for the KDF numbers. */
    private fun number(v: PyJson?, fallback: Int): Long {
        if (v == null || !v.truthy) return fallback.toLong()
        return when (v) {
            is PyJson.Int -> v.v
            is PyJson.Bool -> if (v.v) 1 else 0
            is PyJson.Float -> if (v.v.isFinite() && kotlin.math.abs(v.v) < 1e18) v.v.toLong() else null
            is PyJson.Str -> Py.int(v.v)
            else -> null
        } ?: throw ImportException.malformed("Encrypted export KDF parameters are malformed")
    }

    /** Windows `derive_export_keys`: (encryption key, MAC key). */
    fun keys(password: String, doc: PyJson): Pair<ByteArray, ByteArray> {
        val salt = (doc["salt"] as? PyJson.Str)?.v?.takeIf { it.isNotEmpty() }
            ?: throw ImportException.malformed("Encrypted export is missing its salt")
        val kdfType = doc["kdfType"] ?: PyJson.Int(0)
        val iterations = number(doc["kdfIterations"], 0)
        val secret = password.toByteArray(Charsets.UTF_8)
        val saltBytes = salt.toByteArray(Charsets.UTF_8)
        val master: ByteArray = try {
            when {
                kdfType.equalsNumber(0) -> {
                    if (iterations !in 1..MAX_PBKDF2_ITERATIONS.toLong()) {
                        throw ImportException.malformed("Encrypted export iteration count is outside the supported range")
                    }
                    val gen = PKCS5S2ParametersGenerator(SHA256Digest())
                    gen.init(secret, saltBytes, iterations.toInt())
                    (gen.generateDerivedMacParameters(256) as KeyParameter).key
                }
                kdfType.equalsNumber(1) -> {
                    val memory = number(doc["kdfMemory"], 64)
                    val parallelism = number(doc["kdfParallelism"], 4)
                    if (iterations !in 1..MAX_ARGON2_ITERATIONS.toLong() || memory !in 8..MAX_ARGON2_MEMORY_MIB.toLong() ||
                        parallelism !in 1..MAX_ARGON2_PARALLELISM.toLong()
                    ) {
                        throw ImportException.malformed("Encrypted export Argon2 parameters are outside the supported range")
                    }
                    Argon2.default.derive(
                        secret, MessageDigest.getInstance("SHA-256").digest(saltBytes),
                        (memory * 1024).toInt(), iterations.toInt(), parallelism.toInt(), 32,
                    )
                }
                else -> throw ImportException.malformed("Unsupported Bitwarden KDF type")
            }
        } finally {
            secret.fill(0)
        }
        fun expand(info: String): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(master, "HmacSHA256"))
            mac.update(info.toByteArray(Charsets.US_ASCII))
            mac.update(1)
            return mac.doFinal()
        }
        val out = expand("enc") to expand("mac")
        master.fill(0)
        return out
    }

    /** Windows `decrypt_enc_string`. */
    fun open(value: PyJson, encKey: ByteArray, macKey: ByteArray): ByteArray {
        val s = (value as? PyJson.Str)?.v
        if (s == null || !s.startsWith("2.")) throw ImportException.malformed("Unsupported Bitwarden encryption string type")
        val parts = s.substring(2).split('|')
        if (parts.size != 3) throw ImportException.malformed("Bitwarden encryption string is malformed")
        val decoded = parts.map {
            try {
                java.util.Base64.getDecoder().decode(it)
            } catch (e: IllegalArgumentException) {
                throw ImportException.malformed("Bitwarden encryption string is not valid Base64")
            }
        }
        val (iv, ciphertext, mac) = decoded
        if (iv.size != 16 || mac.size != 32 || ciphertext.isEmpty() || ciphertext.size % 16 != 0) {
            throw ImportException.malformed("Bitwarden encryption string has unexpected lengths")
        }
        val h = Mac.getInstance("HmacSHA256")
        h.init(SecretKeySpec(macKey, "HmacSHA256"))
        h.update(iv)
        h.update(ciphertext)
        if (!MessageDigest.isEqual(h.doFinal(), mac)) throw ImportException(ImportException.Kind.WRONG_PASSWORD)
        return try {
            val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(iv))
            c.doFinal(ciphertext)
        } catch (e: Exception) {
            throw ImportException.malformed("Encrypted export padding is invalid")
        }
    }
}
