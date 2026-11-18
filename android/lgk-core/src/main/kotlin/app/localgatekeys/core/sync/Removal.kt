package app.localgatekeys.core.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.primitives.Identifier

/** A notice or watch file that is not accepted; [reason] is the desktop `RemovalError.reason` code. */
class RemovalException(val reason: String) : Exception(reason)

/** A verified (or just parsed) removal notice: [signer] removed [deviceId] from [groupId] at [epoch]. */
data class RemovalNotice(val groupId: String, val deviceId: String, val epoch: Long, val signer: String, val issuedAt: Long)

/**
 * The watch file (desktop `removal.Watch`, `<vault>.sync-watch.json`): what this device trusted at its last folder
 * run, so a removal notice can be checked while the vault is locked. Only ids, the epoch, the folder and public keys.
 */
data class RemovalWatch(
    val groupId: String,
    val deviceId: String,
    val epoch: Long,
    val installId: String,
    val folder: String,
    /** Device id -> base64 Ed25519 signing key of each member that may sign a notice for this device. */
    val signers: Map<String, String>,
) {
    /** Canonical JSON (the bytes the desktop writes). */
    fun encode(): ByteArray = CanonicalJson.encode(
        JsonValue.Obj(
            mapOf(
                "version" to JsonValue.Int(Removal.WATCH_VERSION),
                "group_id" to JsonValue.Str(groupId),
                "device_id" to JsonValue.Str(deviceId),
                "epoch" to JsonValue.Int(epoch),
                "install_id" to JsonValue.Str(installId),
                "folder" to JsonValue.Str(folder),
                "signers" to JsonValue.Obj(signers.mapValues { JsonValue.Str(it.value) }),
            ),
        ),
        Dialect.UTF8,
    )

    /** The folder path is the user's; the keys are public, but not needed in logs either. */
    override fun toString(): String = "RemovalWatch(group=$groupId, device=$deviceId, epoch=$epoch, signers=${signers.size})"
}

/**
 * Where the watch file lives and how it is written (the app: a plain file next to the vault directory). [folder] is
 * what the watch file records as the cloud folder (the app: the folder's tree URI), so a locked check can open it.
 */
interface RemovalWatchStore {
    val folder: String

    /** The stored bytes (at most [Removal.MAX_WATCH_BYTES] + 1), or null when there is none. */
    fun read(): ByteArray?

    /** Replace the file atomically. */
    fun write(data: ByteArray)

    fun delete()
}

/**
 * Signed removal notices (desktop `localvault.sync.removal`; design `docs/design/security-2026-10-30/wp-a-design.md`,
 * vectors `tests/vectors/sync/removal/`). Only a notice signed by a member this device already trusted, with the
 * folder's keyring no longer listing this device, proves a removal; the inferred issue kinds (`removed-or-conflict`,
 * `rejoin-required`...) never do.
 */
object Removal {
    const val NOTICE_FORMAT: Long = 1
    val NOTICE_LABEL: ByteArray = "localgatekeys|sync|removal-notice|v1|".toByteArray(Charsets.UTF_8)
    const val REMOVED_DIR_NAME = "removed"
    const val REMOVED_DIR = "${FolderLayout.SYNC_DIR}/$REMOVED_DIR_NAME"
    const val NOTICE_SUFFIX = ".lgkremoved"
    const val MAX_NOTICE_BYTES = 4096
    const val WATCH_VERSION: Long = 1
    const val WATCH_SUFFIX = ".sync-watch.json"
    const val MAX_WATCH_BYTES = 16 * 1024
    private const val MAX_INT: Long = (1L shl 53) - 1
    private val NOTICE_FIELDS = setOf("format", "group_id", "device_id", "epoch", "signer", "issued_at", "sig")
    private val WATCH_FIELDS = setOf("version", "group_id", "device_id", "epoch", "install_id", "folder", "signers")

    private fun isInt(v: JsonValue?): Boolean = v is JsonValue.Int && v.v in 0..MAX_INT

    private fun isId(v: JsonValue?): Boolean = v is JsonValue.Str && Identifier.isValid(v.v)

    // ---- notice ----

    fun noticeName(deviceId: String): String = "$deviceId$NOTICE_SUFFIX"

    /** Folder path of [deviceId]'s notice; null unless the id is valid. */
    fun noticePath(deviceId: String): String? = if (Identifier.isValid(deviceId)) "$REMOVED_DIR/${noticeName(deviceId)}" else null

    /** The notice bytes that [signer] removed [deviceId] from [groupId] at [epoch], signed with [sign]. */
    fun makeNotice(groupId: String, deviceId: String, epoch: Long, signer: String, issuedAt: Long, sign: (ByteArray) -> ByteArray): ByteArray {
        if (!Identifier.isValid(groupId) || !Identifier.isValid(deviceId) || !Identifier.isValid(signer) ||
            epoch !in 0..MAX_INT || issuedAt !in 0..MAX_INT || signer == deviceId
        ) {
            throw RemovalException("bad-notice")
        }
        val body = LinkedHashMap<String, JsonValue>()
        body["format"] = JsonValue.Int(NOTICE_FORMAT)
        body["group_id"] = JsonValue.Str(groupId)
        body["device_id"] = JsonValue.Str(deviceId)
        body["epoch"] = JsonValue.Int(epoch)
        body["signer"] = JsonValue.Str(signer)
        body["issued_at"] = JsonValue.Int(issuedAt)
        val sig = sign(NOTICE_LABEL + CanonicalJson.encode(JsonValue.Obj(body), Dialect.UTF8))
        body["sig"] = JsonValue.Str(Base64Std.encode(sig))
        return CanonicalJson.encode(JsonValue.Obj(body), Dialect.UTF8)
    }

    /** [makeNotice] signed by [identity] (the remover), which is the signer. */
    fun makeNotice(identity: DeviceIdentity, groupId: String, deviceId: String, epoch: Long, issuedAt: Long): ByteArray =
        makeNotice(groupId, deviceId, epoch, identity.deviceId, issuedAt) { identity.sign(it) }

    /** (notice, signed message, signature); throws `bad-notice`. The message is rebuilt from the parsed values. */
    fun parseNotice(raw: ByteArray): Triple<RemovalNotice, ByteArray, ByteArray> {
        if (raw.size > MAX_NOTICE_BYTES) throw RemovalException("bad-notice")
        val doc = try {
            CanonicalJson.parse(raw)
        } catch (e: Exception) {
            throw RemovalException("bad-notice")
        }
        val f = (doc as? JsonValue.Obj)?.fields ?: throw RemovalException("bad-notice")
        if (f.keys != NOTICE_FIELDS) throw RemovalException("bad-notice")
        val format = f["format"]
        if (format !is JsonValue.Int || format.v != NOTICE_FORMAT || !isId(f["group_id"]) || !isId(f["device_id"]) ||
            !isId(f["signer"]) || !isInt(f["epoch"]) || !isInt(f["issued_at"]) || f["sig"] !is JsonValue.Str
        ) {
            throw RemovalException("bad-notice")
        }
        val sig = try {
            Base64Std.decodeStrict((f["sig"] as JsonValue.Str).v)
        } catch (e: Exception) {
            throw RemovalException("bad-notice")
        }
        if (sig.size != 64) throw RemovalException("bad-notice")
        val body = f.filterKeys { it != "sig" }
        val notice = RemovalNotice(
            (f["group_id"] as JsonValue.Str).v, (f["device_id"] as JsonValue.Str).v, (f["epoch"] as JsonValue.Int).v,
            (f["signer"] as JsonValue.Str).v, (f["issued_at"] as JsonValue.Int).v,
        )
        return Triple(notice, NOTICE_LABEL + CanonicalJson.encode(JsonValue.Obj(body), Dialect.UTF8), sig)
    }

    private fun key(value: String): ByteArray {
        val raw = try {
            Base64Std.decodeStrict(value)
        } catch (e: Exception) {
            throw RemovalException("bad-key")
        }
        if (raw.size != 32) throw RemovalException("bad-key")
        return raw
    }

    /** (group id, epoch, member ids) of a keyring, WITHOUT authenticating it (corroboration only). */
    private fun ringMembers(raw: ByteArray): Triple<String, Long, Set<String>> {
        if (raw.size > Keyring.MAX_KEYRING_BYTES) throw RemovalException("keyring")
        val ring = try {
            CanonicalJson.parse(raw)
        } catch (e: Exception) {
            throw RemovalException("keyring")
        }
        val f = (ring as? JsonValue.Obj)?.fields ?: throw RemovalException("keyring")
        val group = f["group_id"]
        val epoch = f["epoch"]
        val members = f["members"]
        if (!isId(group) || !isInt(epoch) || members !is JsonValue.Arr) throw RemovalException("keyring")
        // Entries that are not objects with a text device id are ignored.
        val ids = members.items.mapNotNull { ((it as? JsonValue.Obj)?.fields?.get("device_id") as? JsonValue.Str)?.v }.toSet()
        return Triple((group as JsonValue.Str).v, (epoch as JsonValue.Int).v, ids)
    }

    /**
     * The notice [raw] if it proves that [watch]'s device was removed; else [RemovalException] with, in order,
     * `bad-notice`, `not-for-this-device`, `stale`, `unknown-signer`, `bad-key`, `bad-signature`, `keyring`.
     * [folderKeyring]: the bytes of the folder's current keyring.
     */
    fun verifyNotice(raw: ByteArray, watch: RemovalWatch, folderKeyring: ByteArray): RemovalNotice {
        val (notice, message, sig) = parseNotice(raw)
        if (notice.groupId != watch.groupId || notice.deviceId != watch.deviceId) throw RemovalException("not-for-this-device")
        if (notice.signer == watch.deviceId || notice.epoch <= watch.epoch) throw RemovalException("stale")
        val key = watch.signers[notice.signer] ?: throw RemovalException("unknown-signer")
        if (!Ed25519.verify(sig, message, key(key))) throw RemovalException("bad-signature")
        val (group, epoch, members) = ringMembers(folderKeyring)
        if (group != watch.groupId || epoch < notice.epoch || watch.deviceId in members) throw RemovalException("keyring")
        return notice
    }

    // ---- watch file ----

    /** The watch file's name for the vault named [vaultName]: its stem + `.sync-watch.json` (desktop `watch_path`). */
    fun watchFileName(vaultName: String): String {
        val dot = vaultName.lastIndexOf('.')
        val stem = if (dot > 0) vaultName.substring(0, dot) else vaultName
        return stem + WATCH_SUFFIX
    }

    /**
     * The watch for a folder member's trusted [state] (desktop `watch_from_state`); null without a keyring. Signers are
     * the members of the trusted keyring with a signing key, except this device, [unacked] (members the user has not
     * confirmed: anyone with the sync password can add one) and invalid ids.
     */
    fun watchFromState(state: SyncGroupState, folder: String, unacked: Collection<String> = state.unackedMembers): RemovalWatch? {
        val bytes = state.keyring ?: return null
        val ring = try {
            if (bytes.size > Keyring.MAX_KEYRING_BYTES) return null
            CanonicalJson.parse(bytes) as? JsonValue.Obj ?: return null
        } catch (e: Exception) {
            return null
        }
        val unconfirmed = unacked.toSet()
        val signers = Keyring.memberSigningKeys(ring)
            .filterKeys { it != state.deviceId && it !in unconfirmed && Identifier.isValid(it) }
        return RemovalWatch(state.groupId, state.deviceId, state.epoch, state.installId, folder, signers)
    }

    /** [fresh] with each signer's key pinned to the one [old] (the stored watch) already had (desktop `pinned`). */
    fun pinned(fresh: RemovalWatch, old: RemovalWatch?): RemovalWatch {
        if (old == null || old.groupId != fresh.groupId || old.deviceId != fresh.deviceId) return fresh
        return fresh.copy(signers = fresh.signers.mapValues { (d, k) -> old.signers[d] ?: k })
    }

    /** The watch file [raw], or null when it is not valid (desktop `load_watch`). */
    fun parseWatch(raw: ByteArray?): RemovalWatch? {
        if (raw == null || raw.size > MAX_WATCH_BYTES) return null
        val doc = try {
            CanonicalJson.parse(raw)
        } catch (e: Exception) {
            return null
        }
        val f = (doc as? JsonValue.Obj)?.fields ?: return null
        if (f.keys != WATCH_FIELDS) return null
        val version = f["version"]
        if (version !is JsonValue.Int || version.v != WATCH_VERSION) return null
        val install = f["install_id"] as? JsonValue.Str
        val folder = f["folder"] as? JsonValue.Str
        val signers = f["signers"] as? JsonValue.Obj
        if (!isId(f["group_id"]) || !isId(f["device_id"]) || !isInt(f["epoch"]) || install == null || install.v.isEmpty() ||
            folder == null || folder.v.isEmpty() || signers == null ||
            !signers.fields.all { (k, v) -> Identifier.isValid(k) && v is JsonValue.Str }
        ) {
            return null
        }
        return RemovalWatch(
            (f["group_id"] as JsonValue.Str).v, (f["device_id"] as JsonValue.Str).v, (f["epoch"] as JsonValue.Int).v,
            install.v, folder.v, signers.fields.mapValues { (it.value as JsonValue.Str).v },
        )
    }

    /** Store [fresh] pinned against the stored watch, unless it already holds that; returns what is stored. Never throws. */
    fun refresh(store: RemovalWatchStore, fresh: RemovalWatch): RemovalWatch {
        val old = try {
            store.read()
        } catch (e: Exception) {
            null
        }
        val watch = pinned(fresh, parseWatch(old))
        val data = watch.encode()
        if (old == null || !old.contentEquals(data)) {
            try {
                store.write(data)
            } catch (e: Exception) {
                // best effort: the next run writes it again
            }
        }
        return watch
    }

    private fun readLimited(access: FolderAccess, path: String, limit: Int): ByteArray? = try {
        access.read(path, limit + 1).takeIf { it.size <= limit }
    } catch (e: Exception) {
        null
    }

    /** The verified notice for [watch]'s device in the folder [access], or null (never throws; desktop `check`). */
    fun check(watch: RemovalWatch, installId: String, access: FolderAccess): RemovalNotice? {
        if (watch.installId != installId) return null
        val path = noticePath(watch.deviceId) ?: return null
        val raw = readLimited(access, path, MAX_NOTICE_BYTES) ?: return null
        val ring = readLimited(access, FolderLayout.KEYRING_PATH, Keyring.MAX_KEYRING_BYTES) ?: return null
        return try {
            verifyNotice(raw, watch, ring)
        } catch (e: Exception) {
            null
        }
    }
}
