package app.localgatekeys.core.backup

import app.localgatekeys.core.crypto.Argon2
import app.localgatekeys.core.importing.ZipEntry
import app.localgatekeys.core.importing.ZipReader
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.CryptoBox
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest

/**
 * Reads a computer's full backup (`.lgk` / `.lgkfull`, Windows `backup.py`, Swift `FullBackupV2`/`FullBackupV3`) and
 * the vault inside it (Windows `vault.py`, Swift `DesktopVaultFile`), for the phone's restore test only: nothing is
 * restored or kept. Read side only, byte-exact with the writers; pinned by `tests/vectors/backup/v2` and `v3`.
 *
 * * v2: Argon2id(backup password) is the AES-256-GCM key of `manifest.bin` and every `data/NNNNNNNN.bin` member.
 * * v3: the backup password derives an X25519 key (HKDF of the Argon2id output, clamped); its key id must match the
 *   header's; the random data key is unwrapped (X25519 with the ephemeral key, HKDF, AES-256-GCM), then the members
 *   are opened as in v2 with the v3 AADs.
 * * The vault (formats 1-3) opens with the master password. Format 4 (key file or YubiKey) is [NeedsFactors].
 *
 * Every member is authenticated (tag, size and SHA-256) before the vault is opened.
 */
object ComputerBackup {
    /** Wrong backup password, or a modified file (the writers do not tell them apart). */
    class WrongBackupPassword : Exception("Wrong backup password or modified full backup")
    /** Wrong master password, or a modified vault. */
    class WrongMasterPassword : Exception("Incorrect master password or modified vault")
    /** A format-4 vault: it also needs its key file or YubiKey, which a phone cannot supply here. */
    class NeedsFactors : Exception("This vault also needs its key file or YubiKey")
    /** Anything else: not a full backup, damaged, unsupported or out of bounds. */
    class Unreadable(message: String) : Exception(message)

    /** The checked backup: how many live items its vault holds and when it was made (Unix seconds, 0 unknown). */
    data class Checked(val items: Int, val createdAt: Long)

    private const val FORMAT = "localgatekeys-full-backup"
    private val AAD_V2 = "localgatekeys|encrypted-full-profile-backup|v2".toByteArray()
    private val AAD_V3 = "localgatekeys|encrypted-full-profile-backup|v3".toByteArray()
    private val KEY_INFO = "localgatekeys|backup-key|x25519|v1".toByteArray()
    private val KEY_ID_PREFIX = "localgatekeys|backup-key-id|v1|".toByteArray()
    private val WRAP_INFO = "localgatekeys|backup-wrap|v1".toByteArray()
    private val WRAP_AAD_PREFIX = "localgatekeys|backup-recipient|v1|".toByteArray()
    private const val SCHEME = "x25519-hkdf-sha256-aes-256-gcm-v1"
    private const val MAX_BACKUP = Int.MAX_VALUE
    private const val MAX_ENTRIES = 20_005
    private const val MAX_MEMBER = 32 * 1024 * 1024
    private const val MAX_HEADER = 64 * 1024

    /** True for a zip container (`PK`): a computer's full backup, not a phone backup (`LGKMBAK1`). */
    fun looksLikeComputerBackup(bytes: ByteArray?): Boolean =
        bytes != null && bytes.size >= 2 && bytes[0] == 'P'.code.toByte() && bytes[1] == 'K'.code.toByte()

    /** Opens [data] with [backupPassword], authenticates every member, then opens the vault with [masterPassword]. */
    fun check(data: ByteArray, backupPassword: String, masterPassword: String): Checked {
        val (reader, members) = container(data)
        val headerBytes = read(reader, members["header.json"] ?: throw Unreadable("Missing full backup header"), MAX_HEADER)
        val header = obj(headerBytes, "Full backup header")
        if (str(header["format"]) != FORMAT) throw Unreadable("Unsupported full backup format")
        val manifestBlob = read(reader, members["manifest.bin"] ?: throw Unreadable("Missing full backup manifest"), MAX_MEMBER + 64)
        if (manifestBlob.size < 28) throw Unreadable("Full backup manifest is truncated")
        val (key, aad, entryCount) = when (int(header["version"])) {
            2L -> v2Key(header, headerBytes, backupPassword)
            3L -> v3Key(header, headerBytes, backupPassword)
            else -> throw Unreadable("Unsupported full backup format")
        }
        try {
            val manifestBytes = openBlob(manifestBlob, key, aad)
            val manifest = obj(manifestBytes, "Full backup manifest")
            val entries = (manifest["entries"] as? JsonValue.Arr)?.items ?: throw Unreadable("Full backup manifest is malformed")
            if (entries.size.toLong() != entryCount) throw Unreadable("Full backup entry count does not match")
            val listed = entries.map { str((it as? JsonValue.Obj)?.fields?.get("member")) ?: throw Unreadable("Full backup manifest is malformed") }
            if (members.keys != setOf("header.json", "manifest.bin") + listed) throw Unreadable("Full backup members do not match its manifest")
            val digest = sha256(manifestBytes)
            var vault: ByteArray? = null
            for (e in entries) {
                val f = (e as JsonValue.Obj).fields
                val member = str(f["member"])!!
                val size = int(f["size"]) ?: throw Unreadable("Full backup manifest is malformed")
                val z = members.getValue(member)
                if (z.uncompressedSize.toLong() != size + 28) throw Unreadable("Full backup member size does not match its manifest")
                val body = openBlob(read(reader, z, MAX_MEMBER + 64 * 1024), key, aad + digest + member.toByteArray())
                if (body.size.toLong() != size || hex(sha256(body)) != str(f["sha256"])) throw WrongBackupPassword()
                if (str(f["kind"]) == "vault") vault = body
            }
            val items = vaultItems(vault ?: throw Unreadable("Full backup is missing required profile data"), masterPassword)
            return Checked(items, int(manifest["created_at"]) ?: 0)
        } finally {
            key.fill(0)
        }
    }

    // MARK: container and headers

    private fun container(data: ByteArray): Pair<ZipReader, Map<String, ZipEntry>> {
        val reader = try {
            ZipReader(data, MAX_BACKUP, MAX_ENTRIES + 2)
        } catch (e: Exception) {
            throw Unreadable("Could not read full backup")
        }
        val list = reader.entries()
        if (list.size !in 4..(MAX_ENTRIES + 2)) throw Unreadable("Full backup has an unexpected number of members")
        val byName = HashMap<String, ZipEntry>()
        for (e in list) {
            val n = e.name
            if (!(n == "header.json" || n == "manifest.bin" || (n.startsWith("data/") && n.endsWith(".bin")))) throw Unreadable("Unsafe full backup member")
            if (e.flags and 1 != 0 || e.method != 0) throw Unreadable("Full backup members must be stored, not compressed or encrypted")
            if (e.uncompressedSize > MAX_MEMBER + 64 * 1024) throw Unreadable("Full backup member is too large")
            if (byName.put(n, e) != null) throw Unreadable("Unsafe full backup member")
        }
        return reader to byName
    }

    private data class Kdf(val t: Int, val m: Int, val p: Int, val salt: ByteArray)

    private fun kdf(o: Map<String, JsonValue>?): Kdf {
        if (o == null || str(o["name"]) != "argon2id") throw Unreadable("Unsupported full backup encryption parameters")
        val t = int(o["time_cost"]); val m = int(o["memory_cost_kib"]); val p = int(o["parallelism"])
        if (t == null || m == null || p == null || t !in 1..10 || m !in 8L * 1024..512L * 1024 || p !in 1..16) {
            throw Unreadable("Unsupported full backup encryption parameters")
        }
        val salt = b64(o["salt"]) ?: throw Unreadable("Malformed full backup KDF salt")
        if (salt.size != 16) throw Unreadable("Malformed full backup KDF salt")
        return Kdf(t.toInt(), m.toInt(), p.toInt(), salt)
    }

    private fun cipherOk(c: Map<String, JsonValue>?) =
        c != null && str(c["name"]) == "aes-256-gcm" && int(c["nonce_bytes"]) == 12L && int(c["tag_bytes"]) == 16L

    private fun entryCount(header: Map<String, JsonValue>): Long =
        int(header["entry_count"])?.takeIf { it in 2..MAX_ENTRIES.toLong() } ?: throw Unreadable("Full backup entry count is invalid")

    /** v2: Argon2id(backup password) is the key; AAD = AAD_V2 || header bytes. */
    private fun v2Key(header: Map<String, JsonValue>, headerBytes: ByteArray, password: String): Triple<ByteArray, ByteArray, Long> {
        if (!cipherOk((header["cipher"] as? JsonValue.Obj)?.fields)) throw Unreadable("Unsupported full backup encryption parameters")
        val k = kdf((header["kdf"] as? JsonValue.Obj)?.fields)
        (header["kdf"] as JsonValue.Obj).fields["hash_len"]?.let { if (int(it) != 32L) throw Unreadable("Unsupported full backup encryption parameters") }
        val count = entryCount(header)
        return Triple(argon(password, k), AAD_V2 + headerBytes, count)
    }

    /** v3: the backup key from the password, its key id checked, then the data key unwrapped. */
    private fun v3Key(header: Map<String, JsonValue>, headerBytes: ByteArray, password: String): Triple<ByteArray, ByteArray, Long> {
        val rcpt = (header["recipient"] as? JsonValue.Obj)?.fields ?: throw Unreadable("Unsupported full backup format")
        if (!cipherOk((header["cipher"] as? JsonValue.Obj)?.fields) || str(rcpt["scheme"]) != SCHEME) {
            throw Unreadable("Unsupported full backup encryption parameters")
        }
        val k = kdf((rcpt["kdf"] as? JsonValue.Obj)?.fields)
        val count = entryCount(header)
        val keyId = str(rcpt["key_id"]) ?: throw Unreadable("Malformed full backup recipient")
        val epk = b64(rcpt["ephemeral_public_key"])?.takeIf { it.size == 32 } ?: throw Unreadable("Malformed full backup recipient")
        val wrapped = b64(rcpt["wrapped_key"])?.takeIf { it.size == 48 } ?: throw Unreadable("Malformed full backup recipient")
        // The AADs come from canonical bytes, so a header.json that is not canonical is a modified file.
        val headerValue = JsonValue.Obj(header)
        if (!CanonicalJson.encode(headerValue, Dialect.UTF8).contentEquals(headerBytes)) throw WrongBackupPassword()
        val core = JsonValue.Obj(header - "recipient")
        val body = JsonValue.Obj(rcpt - "wrapped_key")
        val wrapAad = WRAP_AAD_PREFIX + CanonicalJson.encode(JsonValue.Obj(mapOf("header" to core, "recipient" to body)), Dialect.UTF8)
        val coreBytes = CanonicalJson.encode(core, Dialect.UTF8)

        val seed = argon(password, k)
        val sk = CryptoBox.hkdf(seed, ByteArray(32), KEY_INFO, 32)
        seed.fill(0)
        sk[0] = (sk[0].toInt() and 0xF8).toByte()
        sk[31] = ((sk[31].toInt() and 0x7F) or 0x40).toByte()
        try {
            val pk = ByteArray(32).also { X25519.scalarMultBase(sk, 0, it, 0) }
            if (hex(sha256(KEY_ID_PREFIX + pk).copyOf(16)) != keyId) throw WrongBackupPassword()
            val shared = ByteArray(32)
            if (!X25519.calculateAgreement(sk, 0, epk, 0, shared, 0) || shared.all { it == 0.toByte() }) throw WrongBackupPassword()
            val kek = CryptoBox.hkdf(shared, epk + pk, WRAP_INFO, 32)
            shared.fill(0)
            val dataKey = try {
                CryptoBox.openGcm(kek, ByteArray(12), wrapped, wrapAad)
            } catch (e: Exception) {
                throw WrongBackupPassword()
            } finally {
                kek.fill(0)
            }
            return Triple(dataKey, AAD_V3 + coreBytes, count)
        } finally {
            sk.fill(0)
        }
    }

    // MARK: vault

    private const val VAULT_V3 = "localgatekeys-vault-v3"
    private const val VAULT_V2 = "localgatekeys-vault-v2"
    private const val CATALOG = "localgatekeys-catalog"
    private val AAD_VAULT_V1 = "localvault-prototype|vault|v1|".toByteArray()
    private val AAD_VAULT_V2 = "localgatekeys|vault|v2|".toByteArray()
    private val AAD_CATALOG = "localgatekeys|vault|v3|".toByteArray()
    private val AAD_WRAPPER = "localgatekeys|vault-key-wrapper|v3|".toByteArray()

    /** The live records (`entries` + `items`) of the backed-up vault opened with [master]. */
    fun vaultItems(vault: ByteArray, master: String): Int {
        if (master.isEmpty()) throw WrongMasterPassword()
        val h = obj(vault, "Vault")
        val version = int(h["version"]) ?: throw Unreadable("Unsupported vault format version")
        if (version == 4L) throw NeedsFactors()
        if (version !in 1..3) throw Unreadable("Unsupported vault format version")
        val cipher = (h["cipher"] as? JsonValue.Obj)?.fields
        if (cipher == null || str(cipher["name"]) != "aes-256-gcm") throw Unreadable("Unsupported vault cipher")
        val kdfObj = (h["kdf"] as? JsonValue.Obj) ?: throw Unreadable("Vault KDF metadata is missing")
        val kdf = vaultKdf(kdfObj.fields)
        val catalogVersion: Long
        val dataKey: ByteArray
        val catalogAad: ByteArray
        if (version == 3L) {
            if (str(h["format"]) != VAULT_V3) throw Unreadable("Unsupported vault format identifier")
            catalogVersion = int(h["catalog_version"]) ?: 2
            val pw = ((h["wrappers"] as? JsonValue.Obj)?.fields?.get("password") as? JsonValue.Obj)?.fields
                ?: throw Unreadable("Vault has no master-password key wrapper")
            val nonce = b64(pw["nonce"])?.takeIf { it.size == 12 } ?: throw Unreadable("Vault key wrapper is malformed")
            val wrapped = b64(pw["ciphertext"])?.takeIf { it.size == 48 } ?: throw Unreadable("Vault key wrapper is malformed")
            val kek = argon(master, kdf)
            val identity = identity(h)
            val wrapperAad = AAD_WRAPPER + CanonicalJson.encode(
                JsonValue.Obj(identity + mapOf("wrapper" to JsonValue.Str("password"), "metadata" to JsonValue.Obj(mapOf("kdf" to kdfObj)))),
                Dialect.ASCII,
            )
            dataKey = try {
                CryptoBox.openGcm(kek, nonce, wrapped, wrapperAad)
            } catch (e: Exception) {
                throw WrongMasterPassword()
            } finally {
                kek.fill(0)
            }
            val body = HashMap(identity)
            body["generation"] = h["generation"] ?: JsonValue.Int(0)
            body["cipher"] = JsonValue.Obj(mapOf("name" to JsonValue.Str("aes-256-gcm")))
            h["throttle_binding"]?.let { body["throttle_binding"] = it }
            catalogAad = AAD_CATALOG + CanonicalJson.encode(JsonValue.Obj(body), Dialect.ASCII)
        } else {
            if (version == 2L && (str(h["format"]) != VAULT_V2 || str(h["catalog"]) != CATALOG)) {
                throw Unreadable("Unsupported vault format identifier")
            }
            catalogVersion = version
            dataKey = argon(master, kdf)
            val body = HashMap<String, JsonValue>()
            body["version"] = JsonValue.Int(version)
            body["kdf"] = h["kdf"] ?: JsonValue.Null
            body["cipher"] = JsonValue.Obj(mapOf("name" to JsonValue.Str("aes-256-gcm")))
            if (version == 2L) {
                body["format"] = h["format"] ?: JsonValue.Str(VAULT_V2)
                body["catalog"] = h["catalog"] ?: JsonValue.Str(CATALOG)
            }
            catalogAad = (if (version == 2L) AAD_VAULT_V2 else AAD_VAULT_V1) + CanonicalJson.encode(JsonValue.Obj(body), Dialect.ASCII)
        }
        try {
            val nonce = b64(cipher["nonce"])?.takeIf { it.size == 12 } ?: throw Unreadable("Vault nonce has an invalid length")
            val ciphertext = b64(cipher["ciphertext"]) ?: throw Unreadable("Vault contains invalid base64 data")
            val plain = try {
                CryptoBox.openGcm(dataKey, nonce, ciphertext, catalogAad)
            } catch (e: Exception) {
                throw WrongMasterPassword()
            }
            val payload = (try { CanonicalJson.parse(plain) } catch (e: Exception) { throw WrongMasterPassword() }) as? JsonValue.Obj
                ?: throw Unreadable("Unsupported decrypted vault payload")
            if (int(payload.fields["version"]) != catalogVersion) throw Unreadable("Unsupported decrypted vault payload")
            return listOf("entries", "items").sumOf { (payload.fields[it] as? JsonValue.Arr)?.items?.size ?: 0 }
        } finally {
            dataKey.fill(0)
        }
    }

    /** `vault._v3_identity`. */
    private fun identity(h: Map<String, JsonValue>): Map<String, JsonValue> = mapOf(
        "version" to JsonValue.Int(3),
        "format" to (h["format"] ?: JsonValue.Str(VAULT_V3)),
        "catalog" to (h["catalog"] ?: JsonValue.Str(CATALOG)),
        "catalog_version" to (h["catalog_version"] ?: JsonValue.Int(2)),
        "vault_id" to (h["vault_id"] ?: JsonValue.Str("")),
        "key_generation" to (h["key_generation"] ?: JsonValue.Int(1)),
    )

    private fun vaultKdf(o: Map<String, JsonValue>): Kdf {
        if (str(o["name"]) != "argon2id") throw Unreadable("Unsupported KDF")
        val salt = b64(o["salt"]) ?: throw Unreadable("Vault contains invalid base64 data")
        if (salt.size < 16) throw Unreadable("Vault KDF salt is too short")
        val t = int(o["time_cost"]); val m = int(o["memory_cost_kib"]); val p = int(o["parallelism"])
        if (t == null || m == null || p == null || int(o["hash_len"]) != 32L || t !in 1..10 || m !in 8L * 1024..512L * 1024 || p !in 1..16) {
            throw Unreadable("Invalid KDF parameters")
        }
        return Kdf(t.toInt(), m.toInt(), p.toInt(), salt)
    }

    // MARK: helpers

    private fun argon(password: String, k: Kdf): ByteArray =
        Argon2.default.derive(password.toByteArray(Charsets.UTF_8), k.salt, k.m, k.t, k.p, 32)

    private fun openBlob(blob: ByteArray, key: ByteArray, aad: ByteArray): ByteArray {
        if (blob.size < 28) throw WrongBackupPassword()
        return try {
            CryptoBox.openGcm(key, blob.copyOfRange(0, 12), blob.copyOfRange(12, blob.size), aad)
        } catch (e: Exception) {
            throw WrongBackupPassword()
        }
    }

    private fun read(reader: ZipReader, e: ZipEntry, limit: Int): ByteArray {
        if (e.uncompressedSize > limit) throw Unreadable("Full backup member is too large")
        return try { reader.read(e, limit) } catch (x: Exception) { throw Unreadable("Full backup is truncated") }
    }

    private fun obj(bytes: ByteArray, label: String): Map<String, JsonValue> =
        ((try { CanonicalJson.parse(bytes) } catch (e: Exception) { null }) as? JsonValue.Obj)?.fields
            ?: throw Unreadable("$label is not a JSON object")

    private fun str(v: JsonValue?): String? = (v as? JsonValue.Str)?.v
    private fun int(v: JsonValue?): Long? = (v as? JsonValue.Int)?.v
    private fun b64(v: JsonValue?): ByteArray? = str(v)?.let { try { Base64Std.decodeStrict(it) } catch (e: Exception) { null } }
    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
}
