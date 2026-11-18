package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewHeader
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringJoin
import app.localgatekeys.core.keyring.KeyringParse
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.recovery.Heir
import java.security.MessageDigest

/** A folder group operation (join/attach) was refused; [reason] is a stable code (desktop `FolderSyncError`). */
class FolderSyncException(val reason: String, val detail: String = "") :
    Exception(if (detail.isEmpty()) reason else "$reason: $detail")

/** Peer views accepted in one read, plus the counters and sha256 of every file accepted (or recognised as stale). */
internal class PeerRead {
    val views = ArrayList<PeerView>()
    val issues = ArrayList<SyncIssue>()
    val seen = LinkedHashMap<String, Long>()
    val digests = LinkedHashMap<String, String>()

    /** Device id -> base64 signing key of every accepted view that carried a valid signature. */
    val signers = LinkedHashMap<String, String>()

    /** Generations and witnesses published with the accepted views ([Witness.observation]). */
    val observations = ArrayList<Observation>()

    /** Device id -> view counter of every accepted view that published a generation (format 2 or witness file). */
    val witnessed = LinkedHashMap<String, Long>()

    /** Device id -> view counter of every accepted signed format-1 view without a matching witness file. */
    val unwitnessed = LinkedHashMap<String, Long>()
}

/** Outcome of checking the folder keyring; [key] null means the run must stop. */
internal class TrustedRing(val issues: List<SyncIssue>, val key: GroupKey?, val ring: JsonValue?, val bytes: ByteArray?)

/**
 * The cloud-folder transport (desktop `folder_transport.FolderSync`); see that module's docstring for every rule.
 *
 * Review rule: the store is committed only after every read and check of a run has succeeded, in ONE
 * [ItemStore.commit], and only when something changed. A wrong sync password, a keyring that is not
 * trusted or a corrupt peer file therefore never modifies the store. The reserved own-file counter is part
 * of that commit, which happens before the own file is written, so a counter is never reused.
 */
class FolderSync(
    private val access: FolderAccess,
    val installId: String,
    /** Licence keys this build knows (key id -> raw Ed25519 public key). */
    val licenseKeys: Map<String, ByteArray> = emptyMap(),
    /**
     * Device id -> base64 signing key of every LAN-paired peer (desktop `_paired_keys`): the only key that
     * peer's view signature may carry when the keyring lists none for it, ahead of the signer pinned on
     * first use.
     */
    val pairedKeys: Map<String, String> = emptyMap(),
    /**
     * Nonces of witness files. Separate from a run's [RandomSource] so the views a run writes stay byte-identical to
     * the shared vectors (`from_android/`), which predate witness files.
     */
    private val witnessRandom: RandomSource = SystemRandomSource(),
    /**
     * This device's attachment files (attachment sync, 2026-10-29). Null: documents are neither received nor published
     * and no `attachments/` file is touched (the behaviour before attachment sync).
     */
    private val attachments: AttachmentVault? = null,
    /**
     * This vault's watch file (desktop `<vault>.sync-watch.json`, [Removal]): refreshed from the trusted state on every
     * run that reaches a trusted keyring, deleted when the store has left sync. Null: no watch file is kept (a removal
     * notice is still reported when a run stops).
     */
    private val removalWatch: RemovalWatchStore? = null,
    /**
     * Personal collections (sub-plan 07 Task 5j; desktop `folder_transport` gate): this device writes its signed
     * `.lgkcol` capability file, and collection states are merged and published only when every other member of the
     * accepted keyring wrote a valid one ([FeatureCapability], counter 1). False: the v1 behaviour (no file, no
     * collection states), what an older app does.
     */
    val collections: Boolean = false,
    /** This device's share records ([CollectionShares]): links it speaks for and read-only collections, applied in every run. */
    val collectionShares: CollectionShares = CollectionShares.NONE,
    /**
     * Shared collections (sub-plan 07 Task 5k; desktop `FolderSync(share=)`): this folder holds that share group, not the
     * personal one, and [runOnce] runs it ([runShare]). Null: the personal group (the default; nothing changes for it).
     */
    val share: Share? = null,
) {
    init {
        if (installId.isEmpty() || Scalars.count(installId) > MAX_INSTALL_ID || installId.contains('\u0000')) {
            throw FolderSyncException("bad-install-id", "install id must be a non-empty bounded string")
        }
        if (share != null && !Identifier.isValid(share.groupId)) throw FolderSyncException("bad-share", "share group id is malformed")
    }

    /** Which share group a [FolderSync] runs, and what the app knows at the start of the run. */
    class Share(
        val groupId: String,
        /** Pro on this device: a free device's run does the keyring step only (a repair), then stops with `pro-required`. */
        val isPro: Boolean,
        /** Recently deleted as it is now ([ShareTrash.of] of the app's trash rows). */
        val trash: ShareTrash,
    ) {
        override fun toString(): String = "FolderSync.Share(group=$groupId, pro=$isPro)"
    }

    companion object {
        const val STALE_AFTER_SECONDS: Long = SyncMeta.TOMBSTONE_MAX_AGE_DAYS * 86400
        const val OWN_REFRESH_SECONDS: Long = 30 * 86400
        /** A device rewrites its heartbeat at most this often (desktop `seen.HEARTBEAT_SECONDS`). */
        const val HEARTBEAT_SECONDS: Long = 15 * 60
        const val HEARTBEAT_MAX_BYTES = 64 * 1024
        const val MAX_IGNORED_NAMES = 20
        const val MAX_PEERS_SEEN = 64
        const val MAX_MEMBERS_SEEN = 64
        const val MAX_INSTALL_ID = 128

        /** [checkSignature]: skip this view (never valid base64, so never a key). */
        private const val REFUSED = "\u0000refused"

        /** Highest counter accepted from a device's file without a last-seen counter (desktop `MAX_FILE_COUNTER`). */
        const val MAX_FILE_COUNTER: Long = 1L shl 40

        /** Largest step above the last accepted counter of a device (desktop `MAX_COUNTER_JUMP`). */
        const val MAX_COUNTER_JUMP: Long = 1L shl 24

        /**
         * `rollback` or `implausible-counter` for a peer file's [counter], null to accept it (desktop
         * `counter_verdict`); [last] is the last counter accepted from that device (null: none at this epoch).
         */
        fun counterVerdict(counter: Long, last: Long?): String? {
            if (last == null) return if (counter > MAX_FILE_COUNTER) "implausible-counter" else null
            if (counter < last) return "rollback"
            return if (counter - last > MAX_COUNTER_JUMP) "implausible-counter" else null
        }

        /** Fields cleared on moving to a new epoch: peer counters, digests and signing keys (own key kept). */
        internal fun epochReset(state: SyncGroupState, epoch: Long, key: ByteArray): SyncGroupState = state.copy(
            epoch = epoch, key = key, lastSeen = emptyMap(), peerDigests = emptyMap(),
            viewSigners = state.viewSigners.filterKeys { it == state.deviceId }, witnessCounters = emptyMap(),
        )

        private val restoreKinds = setOf("tampered", "rollback")
        private val nextEpochStopReasons = setOf("tampered", "device-wrap", "key-mismatch")
        private val rejoinReasons = setOf("missed-rotation", "not-member")
        private val tamperReasons = setOf("device-wrap", "key-mismatch")
        private val removedOrConflict = SyncIssue(
            "removed-or-conflict", "This device may have been removed from sync. Re-join if that isn't expected.",
        )
        private val rotationConflict = SyncIssue(
            "rotation-conflict", "another device rotated at the same time; re-join with the newest sync password",
        )

        internal fun keyringKind(reason: String): String {
            if (reason == "group-mismatch") return "folder-has-other-group"
            if (reason in restoreKinds) return reason
            if (reason in rejoinReasons) return "rejoin-required"
            if (reason in tamperReasons) return "tampered"
            return "keyring-corrupt"
        }

        /** True if [ring] does not list this device or lacks its wrap. */
        internal fun unlisted(ring: JsonValue, state: SyncGroupState): Boolean {
            val o = Keyring.obj(ring)
            var listed = false
            var wrapped = false
            val members = o["members"]
            if (members is JsonValue.Arr) {
                listed = members.items.any { Keyring.str(Keyring.obj(it)["device_id"]) == state.deviceId }
            }
            val wraps = o["device_wraps"]
            if (wraps is JsonValue.Obj) wrapped = wraps.fields[state.deviceId] != null
            return !(listed && wrapped)
        }

        /** True if [ring] is at the trusted epoch and our own wrap opens a different key (two rotations from one epoch). */
        internal fun competingRotation(ring: JsonValue, trusted: GroupKey, state: SyncGroupState): Boolean {
            val o = Keyring.obj(ring)
            if (Keyring.str(o["group_id"]) != trusted.groupId || Keyring.int(o["epoch"]) != trusted.epoch) return false
            val other = try {
                KeyringParse.verifyStructure(ring)
                Keyring.unwrapDevice(ring, state.identity)
            } catch (e: Exception) {
                return false
            }
            if (!Keyring.macOk(ring, other)) return false
            return !other.key.contentEquals(trusted.key)
        }

        /**
         * Members to confirm (desktop `_unacked_members`): unconfirmed ones still listed, plus members of [current] (the
         * accepted keyring) this device did not know at its last run, other than itself. This device never adds another
         * member itself, so each arrival was added elsewhere. A state without a recorded member list (`membersEpoch` 0)
         * reports nothing new. At most [MAX_MEMBERS_SEEN].
         */
        internal fun unackedMembers(state: SyncGroupState, current: Set<String>): List<String> {
            val out = HashSet(state.unackedMembers.filter { it in current })
            if (state.membersEpoch != 0L) out.addAll(current - state.members.toSet() - state.deviceId)
            return sortedNames(out).take(MAX_MEMBERS_SEEN)
        }

        /**
         * The member names of [state]'s stored (accepted) keyring, by device id; null for a name that cannot be read.
         * Empty when the state has no keyring or it no longer opens (the screen then shows ids only).
         */
        fun storedMemberNames(state: SyncGroupState): Map<String, String?> = try {
            val bytes = state.keyring
            if (bytes == null) emptyMap() else Keyring.memberNames(Keyring.parse(bytes), state.groupKey())
        } catch (e: Exception) {
            emptyMap()
        }

        /** [acknowledgeMembers] without a folder (it changes only the store): [installId] is this installation's. */
        fun acknowledgeMembers(store: ItemStore, installId: String, deviceIds: Collection<String>): Int = translate {
            val snapshot = store.load()
            val state = snapshot.sync ?: throw FolderSyncException("not-joined")
            if (state.installId != installId) {
                throw FolderSyncException("rejoin-required", "this vault was joined on another installation")
            }
            val chosen = deviceIds.toSet()
            val left = state.unackedMembers.filter { it !in chosen }
            val count = state.unackedMembers.size - left.size
            if (count > 0) store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, state.copy(unackedMembers = left)))
            count
        }

        internal fun memberIds(ring: JsonValue): Set<String> {
            val members = Keyring.obj(ring)["members"] as? JsonValue.Arr ?: return emptySet()
            return members.items.mapNotNull { Keyring.str(Keyring.obj(it)["device_id"]) }.toSet()
        }

        internal fun ignoredIssue(names: List<String>): SyncIssue {
            val shown = names.take(MAX_IGNORED_NAMES).joinToString(", ")
            val more = if (names.size > MAX_IGNORED_NAMES) ", +${names.size - MAX_IGNORED_NAMES} more" else ""
            return SyncIssue("ignored-file", "${names.size} ${if (names.size == 1) "file" else "files"}: $shown$more")
        }

        internal fun sha256Hex(data: ByteArray): String = Hex.lower(MessageDigest.getInstance("SHA-256").digest(data))

        private fun sortedNames(names: Collection<String>): List<String> = names.sortedWith { a, b -> Scalars.compare(a, b) }

        private fun isNotFound(e: Exception) = e is FolderAccessException && e.kind == FolderAccessException.Kind.NOT_FOUND

        private fun <T> translate(body: () -> T): T = try {
            body()
        } catch (e: FolderSyncException) {
            throw e
        } catch (e: KeyringException) {
            throw FolderSyncException(e.reason, e.detail)
        } catch (e: Exception) {
            throw FolderSyncException("folder-error", e.message ?: e.toString())
        }
    }

    // ---- keyring ----

    private fun readKeyringBytes(): ByteArray = access.read(FolderLayout.KEYRING_PATH, Keyring.MAX_KEYRING_BYTES + 1)

    private fun readKeyringOrNull(): ByteArray? = try {
        readKeyringBytes()
    } catch (e: FolderAccessException) {
        if (e.kind == FolderAccessException.Kind.NOT_FOUND) null else throw e
    }

    /** Writes [data] if the folder still holds [expected] (null: no keyring), else `keyring-changed`. */
    private fun writeKeyring(data: ByteArray, expected: ByteArray?) {
        val current = readKeyringOrNull()
        val same = if (current == null || expected == null) current == null && expected == null else current.contentEquals(expected)
        if (!same) throw FolderSyncException("keyring-changed", "another device changed the keyring; try again")
        access.writeAtomic(FolderLayout.KEYRING_PATH, data)
    }

    private fun stop(vararg issues: SyncIssue) = TrustedRing(issues.toList(), null, null, null)

    private fun trustedKeyring(state: SyncGroupState): TrustedRing {
        val raw = try {
            readKeyringBytes()
        } catch (e: FolderAccessException) {
            return if (e.kind == FolderAccessException.Kind.NOT_FOUND) {
                stop(SyncIssue("keyring-missing", FolderLayout.KEYRING_NAME))
            } else {
                stop(SyncIssue("keyring-unreadable", (e.message ?: e.toString())))
            }
        } catch (e: Exception) {
            return stop(SyncIssue("keyring-unreadable", (e.message ?: e.toString())))
        }
        val trusted = try {
            state.groupKey()
        } catch (e: Exception) {
            return stop(SyncIssue("local-data", (e.message ?: e.toString())))
        }
        val ring = try {
            Keyring.parse(raw)
        } catch (e: Exception) {
            return stop(SyncIssue("keyring-corrupt", (e.message ?: e.toString())))
        }
        try {
            val gk = Keyring.accept(ring, trusted, state.identity)
            return TrustedRing(emptyList(), gk, ring, raw)
        } catch (error: Exception) {
            val reason = (error as? KeyringException)?.reason ?: "keyring-corrupt"
            val kind = keyringKind(reason)
            val detail = if (reason == kind) (error.message ?: error.toString()) else "$kind: ${error.message ?: error}"
            val o = Keyring.obj(ring)
            val sameGroup = Keyring.str(o["group_id"]) == trusted.groupId
            val epoch = Keyring.int(o["epoch"])
            if (sameGroup && epoch == trusted.epoch + 1 && reason in nextEpochStopReasons) {
                return stop(if (unlisted(ring, state)) removedOrConflict else rotationConflict)
            }
            if (sameGroup && epoch == trusted.epoch && reason == "tampered" && unlisted(ring, state)) {
                return stop(removedOrConflict)
            }
            if (reason == "tampered" && competingRotation(ring, trusted, state)) return stop(rotationConflict)
            if (kind in restoreKinds && !(epoch != null && epoch > trusted.epoch)) {
                val restored = restoreKeyring(state, trusted)
                if (restored != null) {
                    return TrustedRing(listOf(SyncIssue("keyring-restored", detail)), restored.first, restored.second, state.keyring)
                }
            }
            return stop(SyncIssue(kind, detail))
        }
    }

    /** Re-verify the stored keyring and write it back; null if that is impossible. */
    private fun restoreKeyring(state: SyncGroupState, trusted: GroupKey): Pair<GroupKey, JsonValue>? {
        val bytes = state.keyring ?: return null
        return try {
            val ring = Keyring.parse(bytes)
            val gk = Keyring.accept(ring, trusted, state.identity)
            if (gk.epoch != trusted.epoch) return null
            access.writeAtomic(FolderLayout.KEYRING_PATH, bytes)
            gk to ring
        } catch (e: Exception) {
            null
        }
    }

    // ---- device files ----

    /**
     * Reads every peer file; never throws for a single bad file. Signer precedence (desktop `read_peers`):
     * [keyringKeys] (each member's key from the accepted keyring), then [pairedKeys], then [signers]
     * (pinned on first use); a peer with a keyring key or a pin must carry a valid signature by it.
     */
    private fun readPeers(
        gk: GroupKey,
        ownId: String,
        members: Set<String>,
        lastSeen: Map<String, Long>,
        digests: Map<String, String>,
        now: Long,
        signers: Map<String, String> = emptyMap(),
        pairedKeys: Map<String, String> = emptyMap(),
        keyringKeys: Map<String, String> = emptyMap(),
    ): PeerRead {
        val pins = signers + keyringKeys
        val expectedKeys = pairedKeys + keyringKeys
        val out = PeerRead()
        val allowed = HashSet<String>()
        for (m in sortedNames(members - ownId)) {
            if (Identifier.isSafeDeviceFile(m)) allowed.add(m) else out.issues.add(SyncIssue("unsafe-member", m))
        }
        val names = try {
            sortedNames(access.list(FolderLayout.DEVICES_DIR))
        } catch (e: Exception) {
            if (!isNotFound(e)) out.issues.add(SyncIssue("folder-unreadable", (e.message ?: e.toString())))
            return out
        }
        val ignored = ArrayList<String>()
        val suffix = FolderLayout.DEVICE_SUFFIX
        for (name in names) {
            if (name.startsWith(".") && name.endsWith(".tmp")) continue // an in-flight atomic write
            val dev = if (name.endsWith(suffix)) name.dropLast(suffix.length) else ""
            if (dev == ownId) continue
            val path = if (dev in allowed) FolderLayout.deviceFile(dev) else null
            if (path == null) {
                ignored.add(name)
                continue
            }
            val raw = try {
                access.read(path, ViewFile.MAX_BYTES + 1)
            } catch (e: Exception) {
                out.issues.add(SyncIssue("unreadable", "$name: ${e.message ?: e}"))
                continue
            }
            val view: Pair<ViewHeader, List<app.localgatekeys.core.engine.ItemState>>
            try {
                view = ViewFile.decode(raw, gk, dev)
            } catch (e: Exception) {
                val reason = (e as? SyncFormatException)?.reason ?: "corrupt"
                val kind = if (reason == "epoch-mismatch" || reason == "device-mismatch") reason else "corrupt"
                out.issues.add(SyncIssue(kind, "$name: $reason"))
                continue
            }
            val counter = view.first.counter
            val digest = sha256Hex(raw)
            val last = lastSeen[dev]
            if (last != null && counter < last) {
                out.issues.add(SyncIssue("rollback", "$name: counter $counter < $last"))
                continue
            }
            if (last == counter && (digests[dev] ?: digest) != digest) {
                out.issues.add(SyncIssue("suspicious-rewrite", "$name: counter $counter reused"))
                continue
            }
            val signer = checkSignature(dev, name, raw, view.first, pins, expectedKeys, out.issues)
            if (signer == REFUSED) continue
            if (counterVerdict(counter, last) != null) {
                out.issues.add(SyncIssue("implausible-counter", "$name: counter $counter"))
                continue
            }
            out.seen[dev] = counter
            out.digests[dev] = digest
            if (signer != null) out.signers[dev] = signer
            if (view.first.writtenAt < now - STALE_AFTER_SECONDS) {
                out.issues.add(SyncIssue("stale-device", name))
                continue
            }
            out.views.add(PeerView(dev, view.second))
            val obs = Witness.observation(view.first) ?: signer?.let { readWitness(gk, view.first, it) }
            if (obs != null) {
                out.observations.add(obs)
                out.witnessed[dev] = counter
            } else if (signer != null) {
                out.unwitnessed[dev] = counter
            }
        }
        if (ignored.isNotEmpty()) out.issues.add(ignoredIssue(ignored))
        return out
    }

    /**
     * The observation of a format-1 view from its witness file, or null (missing, stale, bad, or signed by another key
     * than [signer], the key that signed the view). Silent: a cloud client may upload the witness after the view.
     */
    private fun readWitness(gk: GroupKey, view: ViewHeader, signer: String): Observation? {
        val path = FolderLayout.witnessFile(view.deviceId) ?: return null
        val sigPath = FolderLayout.witnessSignatureFile(view.deviceId) ?: return null
        return try {
            val raw = access.read(path, Witness.MAX_WITNESS_BYTES + 1)
            val sig = access.read(sigPath, ViewSignature.MAX_BYTES + 1)
            val witness = ViewFile.decode(raw, gk, view.deviceId, maxBytes = Witness.MAX_WITNESS_BYTES, maxRecords = 0)
            if (Base64Std.encode(ViewSignature.verify(sig, raw, witness.first)) != signer) return null
            Witness.observation(view, witness)
        } catch (e: Exception) {
            null
        }
    }

    private fun readSignature(deviceId: String): ByteArray? {
        val path = FolderLayout.signatureFile(deviceId) ?: return null
        return try {
            access.read(path, ViewSignature.MAX_BYTES + 1)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * The base64 key of a validly signed view, null for an accepted unsigned one, [REFUSED] to skip it.
     * [pairedKeys] already holds the keyring keys (which win), [signers] the pins and keyring keys.
     */
    private fun checkSignature(
        dev: String,
        name: String,
        raw: ByteArray,
        header: ViewHeader,
        signers: Map<String, String>,
        pairedKeys: Map<String, String>,
        issues: MutableList<SyncIssue>,
    ): String? {
        val expected = pairedKeys[dev] ?: signers[dev]
        val sig = readSignature(dev)
        var why = "no signature file"
        if (sig != null) {
            try {
                val public = Base64Std.encode(ViewSignature.verify(sig, raw, header))
                if (expected != null && public != expected) {
                    issues.add(SyncIssue("view-forged", "$name: signed by another key"))
                    return REFUSED
                }
                return public
            } catch (e: SyncFormatException) {
                why = e.reason
            }
        }
        if (dev !in signers) return null // a device that never signed (older app): accepted as before
        issues.add(SyncIssue(if (why == "sig-mismatch") "view-forged" else "view-unsigned", "$name: $why"))
        return REFUSED
    }

    /** Deletes this device's leftover temp files (a crash between write and replace). */
    private fun sweepOwnTempFiles(deviceId: String) {
        val prefix = ".$deviceId${FolderLayout.DEVICE_SUFFIX}."
        val names = try {
            access.list(FolderLayout.DEVICES_DIR)
        } catch (e: Exception) {
            return
        }
        for (name in names) {
            if (name.startsWith(prefix) && name.endsWith(".tmp")) {
                try {
                    access.remove("${FolderLayout.DEVICES_DIR}/$name")
                } catch (e: Exception) {
                    // best effort
                }
            }
        }
    }

    private class OwnStatus(
        val needsWrite: Boolean,
        val counter: Long,
        val stale: Boolean,
        val present: Boolean = false,
        val selfSigned: Boolean = false,
        /** View format of the file (1 or 2), 0 when absent or unreadable. */
        val format: Long = 0,
        /** A format-1 file has a valid own-signed witness file for the same counter. */
        val witnessed: Boolean = false,
    )

    private fun ownFileStatus(
        gk: GroupKey,
        state: SyncGroupState,
        ownStates: List<app.localgatekeys.core.engine.ItemState>?,
        now: Long,
    ): OwnStatus {
        val raw: ByteArray
        val view = try {
            val path = FolderLayout.deviceFile(state.deviceId) ?: return OwnStatus(ownStates != null, 0, false)
            raw = access.read(path, ViewFile.MAX_BYTES + 1)
            ViewFile.decode(raw, gk, state.deviceId)
        } catch (e: Exception) {
            return OwnStatus(ownStates != null, 0, false)
        }
        val counter = view.first.counter
        val writtenAt = view.first.writtenAt
        val stale = writtenAt < now - STALE_AFTER_SECONDS
        val sig = readSignature(state.deviceId)
        val selfSigned = sig != null && try {
            ViewSignature.verify(sig, raw, view.first).contentEquals(state.identity.signingPublicKey)
        } catch (e: SyncFormatException) {
            false
        }
        val format = view.first.format
        val witnessed = format == ViewFile.FORMAT && selfSigned &&
            readWitness(gk, view.first, Base64Std.encode(state.identity.signingPublicKey)) != null
        if (ownStates == null) return OwnStatus(false, counter, stale, true, selfSigned, format, witnessed)
        val needs = view.second != ownStates || counter != state.ownCounter || !selfSigned ||
            writtenAt < now - OWN_REFRESH_SECONDS
        return OwnStatus(needs, counter, stale, true, selfSigned, format, witnessed)
    }

    // ---- one run ----

    /**
     * One full folder sync (desktop `run_once`). Never throws: every problem is an issue in the report. [memory]: the
     * unlock session's witness memory (LAN checks may be ahead of the stored generations).
     */
    fun runOnce(store: ItemStore, random: RandomSource, clock: UnixClock, memory: WitnessMemory? = null): RunReport {
        share?.let { return runShare(store, it, random, clock) }
        val now = clock.now
        val snapshot = try {
            store.load()
        } catch (e: Exception) {
            return RunReport(issues = listOf(SyncIssue("local-data", (e.message ?: e.toString()))))
        }
        val loaded = snapshot.sync
        if (loaded == null) {
            // Left or reset: a later notice must not erase this vault.
            try {
                removalWatch?.delete()
            } catch (e: Exception) {
                // best effort
            }
            return RunReport(issues = listOf(SyncIssue("not-joined")))
        }
        var state: SyncGroupState = loaded
        if (state.installId != installId) return RunReport(issues = listOf(SyncIssue("rejoin-required", "install-mismatch")))
        // Like Swift's non-throwing `exists` and Python's `is_dir()`, a folder that cannot be checked
        // (revoked permission, provider error) counts as missing.
        val folderThere = state.hasFolder && try {
            access.exists(FolderLayout.SYNC_DIR)
        } catch (e: Exception) {
            false
        }
        if (!folderThere) {
            return RunReport(issues = listOf(SyncIssue("folder-missing", FolderLayout.SYNC_DIR)))
        }
        val trustedRing = trustedKeyring(state)
        val gk = trustedRing.key
        val ring = trustedRing.ring
        val ringBytes = trustedRing.bytes
        if (gk == null || ring == null || ringBytes == null) {
            return RunReport(issues = trustedRing.issues.ifEmpty { listOf(SyncIssue("keyring-corrupt")) } + removalIssues(state))
        }
        val issues = ArrayList(trustedRing.issues)
        val original = state
        val current = memberIds(ring)
        val unacked = unackedMembers(state, current)
        val watchStore = removalWatch
        if (watchStore != null) {
            // What the app checks for a removal notice, also while the vault is locked.
            Removal.watchFromState(state.copy(epoch = gk.epoch, keyring = ringBytes), watchStore.folder, unacked)
                ?.let { Removal.refresh(watchStore, it) }
        }
        if (gk.epoch != state.epoch) {
            state = epochReset(state, gk.epoch, gk.key).copy(
                membersEpoch = gk.epoch, members = sortedNames(current), keyring = ringBytes,
            )
        }
        val known: Set<String> = if (state.membersEpoch == gk.epoch) state.members.toSet() else emptySet()
        for (dropped in sortedNames(known - current)) issues.add(SyncIssue("member-dropped", dropped))
        if (state.deviceId !in current && state.deviceId !in known) issues.add(SyncIssue("member-dropped", state.deviceId))
        for ((device, name) in Keyring.memberNames(ring, gk).entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            if (name == null) issues.add(SyncIssue("bad-name", device))
        }
        var members = known + current
        if (members.size > MAX_MEMBERS_SEEN) members = current

        if (Identifier.isSafeDeviceFile(state.deviceId)) sweepOwnTempFiles(state.deviceId)
        val ringKeys = Keyring.memberSigningKeys(ring).filterKeys { it != state.deviceId }
        for (device in sortedNames(ringKeys.keys)) {
            val pinned = state.viewSigners[device]
            if (pinned != null && pinned != ringKeys[device]) {
                issues.add(SyncIssue("signer-changed", "$device: the keyring lists another signing key"))
            }
        }
        val peers = readPeers(
            gk, state.deviceId, members, state.lastSeen, state.peerDigests, now,
            signers = state.viewSigners.filterKeys { it != state.deviceId },
            pairedKeys = pairedKeys.filterKeys { it != state.deviceId },
            keyringKeys = ringKeys,
        )
        issues.addAll(peers.issues)
        val knownDevices = members + state.lastSeen.keys + state.deviceId
        // Attachment files first (desktop `attachment_flow.import_missing`): a document is applied only with its file.
        val vault = attachments
        if (vault != null) issues.addAll(Documents.importMissing(vault, peers.views.flatMap { it.states }) { readFolderBlob(it.blob) })
        val present: ((AttachmentRef) -> Boolean)? = vault?.let { v -> { ref: AttachmentRef -> v.has(ref) } }
        // Personal collections sync only when every other member wrote a valid signed collections capability file: the
        // view file is read by all of them (an older app would refuse the states). Desktop `col_signers`.
        val capabilitySigners = state.viewSigners + peers.signers + ringKeys
        val withCollections = collections && (current - state.deviceId).all {
            folderCapable(gk, it, capabilitySigners[it], FeatureCapability.Feature.COLLECTIONS)
        }
        var report = SyncRunner.run(
            snapshot, peers.views, state.deviceId, now, licenseKeys, knownDevices, present, withCollections, collectionShares,
        )
        issues.addAll(report.issues)

        // Rollback witnesses (desktop `run_once` step 9).
        val ownGeneration = Witness.generation(snapshot)
        val checked = Witness.check(
            state.deviceId, ownGeneration ?: 0, if (ownGeneration != null) peers.observations else emptyList(),
            memory?.merged(state) ?: state.peerGenerations, state.rollbackSuspected,
        )
        issues.addAll(checked.issues)
        val witnessKeep = (members + state.lanPeers.map { it.deviceId } + pairedKeys.keys) - state.deviceId
        val peerGenerations = Witness.prune(checked.peerGenerations, witnessKeep)
        memory?.remember(state, peerGenerations)
        val witnessPeers = Witness.pruneIds(state.witnessPeers + checked.capable, witnessKeep)
        // A peer known to publish its generation whose newer view comes without one: the witness file was deleted,
        // damaged or withheld. One run of grace (the view was already there last run) covers a late cloud upload.
        val knownWitnessing = witnessPeers.toSet() + state.witnessCounters.keys
        for ((dev, ctr) in peers.unwitnessed.entries.sortedWith { a, b -> Scalars.compare(a.key, b.key) }) {
            if (dev in knownWitnessing && ctr > (state.witnessCounters[dev] ?: -1) && state.lastSeen[dev] == ctr) {
                issues.add(SyncIssue("witness-missing", dev))
            }
        }
        var witnessCounters = (state.witnessCounters + peers.witnessed).filterKeys { it in witnessKeep }
        if (witnessCounters.size > MAX_PEERS_SEEN) witnessCounters = Witness.prune(witnessCounters, witnessCounters.keys)
        val others = current - state.deviceId
        val inline = ownGeneration != null && others.isNotEmpty() && witnessPeers.containsAll(others)
        val ownWitness = Witness.ownWitness(peerGenerations, witnessKeep, state.deviceId)

        val ownKey = Base64Std.encode(state.identity.signingPublicKey)
        var lastSeen = state.lastSeen + peers.seen
        var digests = state.peerDigests + peers.digests
        // Keyring keys are pinned at once (re-pinning happens only here, from the accepted keyring).
        var signers = state.viewSigners + peers.signers + ringKeys
        if (lastSeen.size > MAX_PEERS_SEEN || digests.size > MAX_PEERS_SEEN || signers.size > MAX_PEERS_SEEN) {
            lastSeen = lastSeen.filterKeys { it in members }
            digests = digests.filterKeys { it in members }
            signers = signers.filterKeys { it in members }
        }
        // Workstream 6: a peer whose newer view was accepted this run was synced with now (local only).
        val accepted = peers.seen.filter { (dev, ctr) -> dev != state.deviceId && ctr > (state.lastSeen[dev] ?: -1) }.keys
        // Publish gating: documents go into the view only when every other member wrote a valid signed capability file.
        val documents = vault != null && others.all { folderCapable(gk, it, signers[it]) }
        // The emergency access plan only when every other member advertised the heir feature (sub-plan 08).
        val heir = others.all { folderCapable(gk, it, signers[it], heir = true) }
        val fullOwn = report.ownStates
        if (fullOwn != null) report = report.copy(ownStates = Heir.publishable(Documents.publishable(fullOwn, documents), heir))
        var newState = state.copy(
            lastSeen = lastSeen, peerDigests = digests, membersEpoch = gk.epoch, members = sortedNames(members),
            keyring = ringBytes, viewSigners = signers, peerGenerations = peerGenerations,
            rollbackSuspected = checked.rollbackSuspected, witnessPeers = witnessPeers, witnessCounters = witnessCounters,
            unackedMembers = unacked,
        ).syncedWith(accepted, now)
        val status = ownFileStatus(gk, state, report.ownStates, now)
        if (status.stale) issues.add(SyncIssue("stale-self", "this device had not synced for over a year"))
        var fileCounter = status.counter
        val signedBefore = state.viewSigners[state.deviceId] == ownKey
        if (status.present && !status.selfSigned &&
            (fileCounter > state.ownCounter || (signedBefore && fileCounter == state.ownCounter))
        ) {
            // Not written by this device: someone holding the group key wrote our file.
            issues.add(
                SyncIssue(
                    "own-file-rewritten",
                    "${state.deviceId}${FolderLayout.DEVICE_SUFFIX}: counter $fileCounter, reserved ${state.ownCounter}",
                ),
            )
            if (fileCounter - state.ownCounter > MAX_COUNTER_JUMP) fileCounter = state.ownCounter
        } else if (fileCounter > state.ownCounter) {
            issues.add(SyncIssue("counter-resynced", "own file counter $fileCounter > reserved ${state.ownCounter}"))
        }
        val base = maxOf(state.ownCounter, fileCounter)
        var needsWrite = status.needsWrite
        var witnessOnly = false
        if (report.ownStates != null && status.present && (
                (status.format == ViewFile.FORMAT && ownGeneration != null && (inline || !status.witnessed)) ||
                    (status.format == ViewFile.FORMAT_WITNESS && !inline)
                )
        ) {
            if (status.format == ViewFile.FORMAT && !inline && status.selfSigned && status.counter == state.ownCounter) {
                witnessOnly = !needsWrite // only the witness file is missing or bad: rewrite just it
            } else {
                needsWrite = true // publish the witness once, in the form every member can read
            }
        }
        if (base >= VersionVector.MAX_COUNTER) {
            // Only a counter stored before the bounds existed can get here; never fail the whole run.
            issues.add(SyncIssue("counter-exhausted", "own counter $base"))
            needsWrite = false
        }
        val counter = base + 1
        if (needsWrite) newState = newState.copy(ownCounter = counter, viewSigners = newState.viewSigners + (state.deviceId to ownKey))

        // Every read and check is done: commit once (records, meta, group state, reserved counter).
        val records = report.records ?: snapshot.records
        val meta = report.meta ?: snapshot.meta
        if (records != snapshot.records || meta != snapshot.meta || newState != original) {
            try {
                store.commit(StoreChange(snapshot.revision, records, meta, newState))
            } catch (e: Exception) {
                issues.add(SyncIssue("busy", (e.message ?: e.toString())))
                return report.copy(issues = issues, wrote = false)
            }
        }

        var wrote = report.wrote
        val own = report.ownStates
        if (vault != null) {
            try {
                writeCapability(gk, state, clock)
            } catch (e: Exception) {
                issues.add(SyncIssue("write-failed", "attachment capability: ${e.message ?: e}"))
            }
        }
        if (collections) {
            try {
                writeCapability(gk, state, clock, FeatureCapability.Feature.COLLECTIONS)
            } catch (e: Exception) {
                issues.add(SyncIssue("write-failed", "collections capability: ${e.message ?: e}"))
            }
        }
        try {
            writeCapability(gk, state, clock, FeatureCapability.Feature.HEIR)
        } catch (e: Exception) {
            issues.add(SyncIssue("write-failed", "heir capability: ${e.message ?: e}"))
        }
        // Heartbeats: when each device last ran here, even with no changes (sync status only, kept in memory).
        try {
            writeHeartbeat(gk, state, clock)
        } catch (e: Exception) {
            issues.add(SyncIssue("write-failed", "heartbeat: ${e.message ?: e}"))
        }
        val trusted = signers + pairedKeys.filterKeys { it != state.deviceId } + ringKeys
        for (peer in sortedNames(others)) {
            val at = readHeartbeat(gk, peer, trusted[peer]) ?: continue
            PeerSeenAt.note(state.groupId, peer, minOf(at, now))
        }
        if (needsWrite && own != null && vault != null && documents) issues.addAll(publishFolderBlobs(vault, own, now))
        if (needsWrite && own != null) {
            val path = FolderLayout.deviceFile(state.deviceId)
            val sigPath = FolderLayout.signatureFile(state.deviceId)
            if (path != null && sigPath != null) {
                try {
                    val raw = if (inline) {
                        ViewFile.encode(gk, state.deviceId, counter, own, clock, random, vaultGeneration = ownGeneration, witness = ownWitness)
                    } else {
                        ViewFile.encode(gk, state.deviceId, counter, own, clock, random)
                    }
                    val header = ViewFile.decodeHeader(raw)
                    val sig = ViewSignature.sign(raw, header, state.identity)
                    val side = if (!inline && ownGeneration != null) {
                        witnessPair(gk, state, counter, ownGeneration, ownWitness, clock, witnessRandom)
                    } else {
                        null
                    }
                    access.writeAtomic(path, raw)
                    access.writeAtomic(sigPath, sig)
                    if (side != null) writeWitnessPair(state.deviceId, side)
                    wrote = true
                } catch (e: SyncFormatException) {
                    issues.add(SyncIssue("too-large", (e.message ?: e.toString())))
                } catch (e: Exception) {
                    issues.add(SyncIssue("write-failed", (e.message ?: e.toString())))
                }
            } else {
                issues.add(SyncIssue("write-failed", "device id is not a safe file name"))
            }
        } else if (witnessOnly && ownGeneration != null) {
            // The view itself is current: write only its witness file (same counter); no counter bump, no store commit.
            try {
                writeWitnessPair(state.deviceId, witnessPair(gk, state, status.counter, ownGeneration, ownWitness, clock, witnessRandom))
            } catch (e: Exception) {
                issues.add(SyncIssue("write-failed", (e.message ?: e.toString())))
            }
        }
        // Sweep unreferenced blobs, only after a run that read a view from every other member.
        if (vault != null && fullOwn != null && peers.views.map { it.deviceId }.toSet().containsAll(others)) {
            sweepBlobs(Documents.refs(fullOwn + peers.views.flatMap { it.states }).map { it.blob }.toSet(), now)
        }
        report = report.copy(issues = issues, wrote = wrote)
        return report
    }

    // ---- shared collections (sub-plan 07 Task 5k; desktop `_share_run`, `_share_keyring`, `_share_removed`) ----
    //
    // A share group syncing through its own cloud folder, same layout as the personal group:
    // - Pro only. Without Pro only the keyring step runs (a repair, an adoption, the owner's removal of this device:
    //   security actions, like removing a member), then the run stops with `pro-required`: no view is read or written.
    //   Never a licence, a document, an attachment, a witness, a heartbeat or a collection state: only the shared
    //   collection's items ([ShareItemStore]).
    // - Keyring: the folder's keyring is adopted ([ShareGroups.adopt]: owner signature, pinned owner/collection/mode,
    //   growth only within an epoch). On the owner's device, a folder keyring that others grew while the owner's own
    //   approvals waited to be written is merged (approvals re-signed over the grown roster, the new joiners pending) and
    //   written (`keyring-merged`). A missing keyring, or one this device's trusted keyring grows from (an older epoch,
    //   fewer members or approvals: a member's tampering included), is replaced by the trusted one (`keyring-restored`).
    //   So that nobody with write access to the folder can stop the share ([ShareGroups.restoresOver]): the owner's device
    //   writes its trusted keyring back over any folder keyring it cannot adopt or reconcile, bytes that do not parse and
    //   another group's keyring included (only a later epoch signed by the pinned owner key is left alone; another group's
    //   keyring is reported as `other-group-replaced`, so two owners writing over each other show up); a member's
    //   device writes back over a keyring of its trusted epoch that does not authenticate (MAC or owner signature). An
    //   authenticated keyring of that epoch that does not grow (a concurrent join) still stops a member's run, and a
    //   member never writes over another group's keyring (`folder-has-other-group`). A rotation that dropped this device:
    //   the owner's removal notice for it (`removed/`) is verified with the pinned owner key only, the collection's items
    //   leave (to Recently deleted, through the app's store) and the group is forgotten (`share-removed`, detail: the
    //   collection id); without a valid notice the run stops with `rejoin-required`. A member whose pending join was lost
    //   to another join at the same moment stops with `superseded` (join again).
    // - Approval: a device the owner has not approved adopts the keyring and stops (`awaiting-approval`): no peer view is
    //   merged and no own view written. Share v2 views are sealed with the content key ([ShareGroups.viewKey]) that only
    //   approved devices can open, so the share password alone opens no item; share v1 views are still sealed with the
    //   group key until the owner upgrades the share. A content wrap that does not open to the committed key stops the run
    //   (`tampered`). A folder keyring of a later format stops the run (`update-required`) and is never written over.
    // - Peers: only members the owner approved (and the owner), each view signed with its keyring key (the owner's with
    //   its pinned key). Read-only shares: a member merges only the owner's view and the owner merges none, so only the
    //   owner's edits flow, whatever a member's file holds.
    // - One commit for the merge and the share's state (the reserved counter included), then the own view (format 1,
    //   signed).

    private fun stopShare(kind: String, detail: String = "") = RunReport(issues = listOf(SyncIssue(kind, detail)))

    private fun why(e: Exception): String = e.message ?: e.javaClass.simpleName

    /** One run of a share group's folder. Never throws: every problem is an issue in the report; `records`/`meta` stay null. */
    private fun runShare(store: ItemStore, share: Share, random: RandomSource, clock: UnixClock): RunReport {
        val now = clock.now
        val groupId = share.groupId
        val main = try {
            store.load()
        } catch (e: Exception) {
            return stopShare("local-data", why(e))
        }
        val record = try {
            ShareGroups.records(main)[groupId]
        } catch (e: Exception) {
            return stopShare("state-corrupt", groupId)
        } ?: return stopShare("not-joined", groupId)
        if (record.state.installId != installId) return stopShare("rejoin-required", "install-mismatch")
        val issues = ArrayList<SyncIssue>()
        val stop = shareKeyring(store, record, share, issues)
        if (!share.isPro) {
            // Pro ended: the keyring step above still ran (a repair is a security action, like removing a member; final
            // review A2); no view is read or written.
            return RunReport(issues = (stop?.issues ?: issues) + SyncIssue("pro-required", groupId))
        }
        stop?.let { return it }

        val shareStore = ShareItemStore(store, groupId, share.trash)
        val view = try {
            shareStore.projection()
        } catch (e: ShareGroupException) {
            return if (e.reason == "bad-state") stopShare("state-corrupt", groupId) else stopShare("local-data", why(e))
        } catch (e: Exception) {
            return stopShare("local-data", why(e))
        }
        val info = view.record
        val state = info.state
        val ring = try {
            ShareKeyring.parse(state.keyring ?: throw KeyringException("missing"))
        } catch (e: Exception) {
            null
        }
        val trustedKey = try {
            state.groupKey()
        } catch (e: Exception) {
            null
        }
        if (ring == null || trustedKey == null) return stopShare("keyring-corrupt", "no trusted keyring")
        val own = state.deviceId
        val owner = info.pin.owner
        val approved = (ShareKeyring.approvedMembers(ring) ?: emptySet()) + owner
        // Share v2: the content key only approved devices hold; share v1: the group key (desktop `view_key`).
        val gk = try {
            if (own in approved) ShareGroups.viewKey(info) else null
        } catch (e: KeyringException) {
            return RunReport(issues = issues + SyncIssue("tampered", why(e)))
        } catch (e: Exception) {
            return stopShare("keyring-corrupt", why(e))
        }
        if (gk == null) {
            // Not approved yet: the keyring was adopted above, but no peer view is merged and no own view is written until
            // the owner lets this device in (share v2: it cannot open them either).
            issues.add(SyncIssue("awaiting-approval", groupId))
            return RunReport(issues = issues)
        }
        // Read-only: only the owner's edits flow; the owner reads nobody.
        val members = (if (info.pin.sharedMode == "read") setOf(owner) else approved)
            .filter { it != own && Identifier.isSafeDeviceFile(it) }.toSet()
        val ringKeys = HashMap(Keyring.memberSigningKeys(ring).filterKeys { it in members })
        if (owner in members) ringKeys[owner] = info.pin.ownerKey
        val peers = readPeers(
            gk, own, members, state.lastSeen, state.peerDigests, now,
            signers = state.viewSigners.filterKeys { it in members }, keyringKeys = ringKeys,
        )
        issues.addAll(peers.issues)
        val (views, refused) = view.filter(peers.views)
        issues.addAll(refused)
        var report = SyncRunner.run(view.snapshot, views, own, now, known = approved + state.lastSeen.keys)
        issues.addAll(report.issues)

        val ownKey = Base64Std.encode(state.identity.signingPublicKey)
        val keep = approved + own
        val accepted = peers.seen.filter { (dev, ctr) -> ctr > (state.lastSeen[dev] ?: -1) }.keys
        var newState = state.copy(
            lastSeen = (state.lastSeen + peers.seen).filterKeys { it in keep },
            peerDigests = (state.peerDigests + peers.digests).filterKeys { it in keep },
            viewSigners = (state.viewSigners + peers.signers + ringKeys).filterKeys { it in keep },
        ).syncedWith(sortedNames(accepted), now)
        val status = ownFileStatus(gk, state, report.ownStates, now)
        var fileCounter = status.counter
        if (status.present && !status.selfSigned && fileCounter > state.ownCounter) {
            issues.add(SyncIssue("own-file-rewritten", "$own${FolderLayout.DEVICE_SUFFIX}"))
            if (fileCounter - state.ownCounter > MAX_COUNTER_JUMP) fileCounter = state.ownCounter
        }
        val counter = maxOf(state.ownCounter, fileCounter) + 1
        var needsWrite = status.needsWrite && report.ownStates != null
        if (needsWrite && counter > VersionVector.MAX_COUNTER) {
            issues.add(SyncIssue("counter-exhausted", "own counter ${counter - 1}"))
            needsWrite = false
        }
        if (needsWrite) newState = newState.copy(ownCounter = counter, viewSigners = newState.viewSigners + (own to ownKey))
        // Every read and check is done: one commit (the share's items, memberships, meta and state, the counter reserved
        // before the file carrying it is written).
        val records = report.records ?: view.snapshot.records
        val meta = report.meta ?: view.snapshot.meta
        report = report.copy(records = null, meta = null)
        if (records != view.snapshot.records || meta != view.snapshot.meta || newState != state) {
            try {
                shareStore.commit(StoreChange(view.snapshot.revision, records, meta, newState))
            } catch (e: Exception) {
                issues.add(SyncIssue("busy", why(e)))
                return report.copy(issues = issues, wrote = false)
            }
        }
        var wrote = false
        val ownStates = report.ownStates
        if (needsWrite && ownStates != null) {
            val path = FolderLayout.deviceFile(own)
            val sigPath = FolderLayout.signatureFile(own)
            if (path != null && sigPath != null) {
                try {
                    val raw = ViewFile.encode(gk, own, counter, ownStates, clock, random)
                    val sig = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), state.identity)
                    access.writeAtomic(path, raw)
                    access.writeAtomic(sigPath, sig)
                    wrote = true
                } catch (e: SyncFormatException) {
                    issues.add(SyncIssue("too-large", why(e)))
                } catch (e: Exception) {
                    issues.add(SyncIssue("write-failed", why(e)))
                }
            } else {
                issues.add(SyncIssue("write-failed", "device id is not a safe file name"))
            }
        }
        return report.copy(issues = issues, wrote = wrote)
    }

    /** Bring the folder keyring and the trusted one together (desktop `_share_keyring`); a report means the run stops. */
    private fun shareKeyring(store: ItemStore, record: ShareRecord, share: Share, issues: MutableList<SyncIssue>): RunReport? {
        val state = record.state
        var stored = state.keyring ?: return stopShare("keyring-corrupt", "no trusted keyring")
        val raw = try {
            readKeyringOrNull()
        } catch (e: Exception) {
            return stopShare("keyring-unreadable", why(e))
        }
        if (raw != null && raw.contentEquals(stored)) return null
        var merged = false
        var otherGroup = false
        val folderRing: JsonValue? = if (raw == null) null else {
            val parsed = try {
                ShareGroups.parseLoose(raw)
            } catch (e: Exception) {
                // Bytes that do not parse: the owner writes its keyring back; a member waits for it.
                if (!ShareGroups.restoresOver(record, null)) return stopShare("keyring-corrupt", why(e))
                null
            }
            // A later app version wrote it (share keyring format above 3): never write an older keyring over it.
            if (parsed != null && KeyringParse.isNewerFormat(parsed)) return stopShare("update-required", FolderLayout.KEYRING_NAME)
            if (parsed != null && (Keyring.str(Keyring.obj(parsed)["group_id"]) ?: "") != state.groupId) {
                if (!ShareGroups.restoresOver(record, parsed)) return stopShare("folder-has-other-group", FolderLayout.KEYRING_NAME)
                otherGroup = Keyring.str(Keyring.obj(parsed)["group_id"]) != null
                null
            } else {
                parsed
            }
        }
        if (raw != null && folderRing != null) {
            try {
                ShareGroups.adopt(store, state.groupId, raw)
                return null
            } catch (e: ShareGroupException) {
                return stopShare(e.reason, e.detail)
            } catch (e: KeyringException) {
                if (e.reason == "removed") return shareRemoved(store, record, raw, e.reason, share)
                val reconciled = try {
                    ShareGroups.reconcileOwner(store, state.groupId, raw)
                } catch (x: Exception) {
                    return stopShare("busy", why(x))
                }
                if (reconciled) {
                    // The owner's approvals, re-signed over the folder's grown roster: write that.
                    stored = try {
                        ShareGroups.records(store.load())[state.groupId]?.state?.keyring
                    } catch (x: Exception) {
                        null
                    } ?: return stopShare("local-data", "the merged keyring cannot be read back")
                    merged = true
                    issues.add(SyncIssue("keyring-merged", FolderLayout.KEYRING_NAME))
                } else if (try {
                        ShareKeyring.growsFrom(folderRing, ShareKeyring.parse(stored))
                    } catch (x: Exception) {
                        false
                    }
                ) {
                    // The folder is behind this device: the trusted keyring is written back below.
                } else if (ShareGroups.supersededJoin(record, folderRing)) {
                    // Someone joined at the same moment and this device's join was lost: join again.
                    return stopShare("superseded", state.groupId)
                } else if (ShareGroups.restoresOver(record, folderRing)) {
                    // The owner's keyring over anything else; a member's over a copy that fails to authenticate.
                } else {
                    if (e.reason in rejoinReasons) return shareRemoved(store, record, raw, e.reason, share)
                    return stopShare(keyringKind(e.reason), why(e))
                }
            } catch (e: Exception) {
                return stopShare("busy", why(e))
            }
        }
        try {
            writeKeyring(stored, raw)
        } catch (e: FolderSyncException) {
            return stopShare(e.reason, e.detail)
        } catch (e: Exception) {
            return stopShare("write-failed", "keyring: ${why(e)}")
        }
        // Another share's keyring that the owner replaced is said apart (final review A1): two owners of different groups
        // in one folder would otherwise overwrite each other without a word.
        if (raw != null && !merged) {
            issues.add(SyncIssue(if (otherGroup) "other-group-replaced" else "keyring-restored", FolderLayout.KEYRING_NAME))
        }
        return null
    }

    /** The folder's keyring no longer lets this device in: act on the owner's notice, if there is one (desktop `_share_removed`). */
    private fun shareRemoved(store: ItemStore, record: ShareRecord, folderRaw: ByteArray, reason: String, share: Share): RunReport {
        val notice = readShareNotice(record.state.deviceId) ?: return stopShare("rejoin-required", reason)
        try {
            ShareGroups.applyShareRemoval(store, record.groupId, notice, folderRaw, share.trash)
        } catch (e: RemovalException) {
            return stopShare("rejoin-required", "$reason; notice refused (${e.reason})")
        } catch (e: ShareGroupException) {
            // Recently deleted full, or the store refused: nothing changed, the next run tries again.
            return stopShare(e.reason, e.detail)
        } catch (e: Exception) {
            return stopShare("item-error", why(e))
        }
        return stopShare("share-removed", record.collectionId)
    }

    /** The removal notice for [deviceId] in the folder; null when missing, too large or unreadable. */
    private fun readShareNotice(deviceId: String): ByteArray? {
        val path = Removal.noticePath(deviceId) ?: return null
        val raw = try {
            access.read(path, Removal.MAX_NOTICE_BYTES + 1)
        } catch (e: Exception) {
            return null
        }
        return if (raw.size <= Removal.MAX_NOTICE_BYTES) raw else null
    }

    /**
     * Writes the owner's removal [notice] for [deviceId] ([ShareGroups.removeMember]) before the rotated keyring; false
     * when it could not be written.
     */
    fun publishShareNotice(deviceId: String, notice: ByteArray): Boolean {
        val path = Removal.noticePath(deviceId) ?: return false
        return try {
            access.writeAtomic(path, notice)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Puts this device's trusted keyring of the share group into the folder now (after create, join, approve or remove;
     * the share run also does it). False when the folder holds something else it may not replace or cannot be written.
     */
    fun writeShareKeyring(store: ItemStore, groupId: String): Boolean {
        val ring = try {
            ShareGroups.records(store.load())[groupId]?.state?.keyring
        } catch (e: Exception) {
            null
        } ?: return false
        val current = try {
            readKeyringOrNull()
        } catch (e: Exception) {
            return false
        }
        if (current != null && current.contentEquals(ring)) return true
        if (current != null) {
            // Only over an older state of the same group (never another group's keyring). Bytes that do not even parse
            // are not replaced here either (fails closed: false); the next share run reports `keyring-corrupt` and the
            // user clears the folder. Desktop `_write_keyring` would overwrite them.
            val grows = try {
                val folder = ShareGroups.parseLoose(current)
                // A keyring a later app version wrote is never replaced (`update-required` in the share run).
                !KeyringParse.isNewerFormat(folder) && ShareKeyring.growsFrom(folder, ShareKeyring.parse(ring))
            } catch (e: Exception) {
                false
            }
            if (!grows) return false
        }
        return try {
            writeKeyring(ring, current)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Whether the folder already holds a sync group's keyring (a new share refuses it: `folder-in-use`). A folder that
     * cannot be checked counts as holding one (fails closed: no share is created over it).
     */
    fun holdsKeyring(): Boolean = try {
        access.exists(FolderLayout.KEYRING_PATH)
    } catch (e: Exception) {
        true
    }

    /**
     * `removal-notice` (detail: the signer) when a member this device trusted signed that it was removed (desktop
     * `_removal_issues`); checked only when a run stops without a trusted keyring. Never throws.
     */
    private fun removalIssues(state: SyncGroupState): List<SyncIssue> = try {
        val store = removalWatch
        val fresh = Removal.watchFromState(state, store?.folder ?: "")
        val watch = if (fresh == null) null else if (store != null) Removal.refresh(store, fresh) else fresh
        val notice = watch?.let { Removal.check(it, installId, access) }
        if (notice == null) emptyList() else listOf(SyncIssue("removal-notice", notice.signer))
    } catch (e: Exception) {
        emptyList()
    }

    // ---- attachments (desktop `attachment_flow`) ----

    /** The verified blob [blobId] from the folder, or null when missing, too large or not matching its name. */
    private fun readFolderBlob(blobId: String): ByteArray? {
        val path = FolderLayout.blobFile(blobId) ?: return null
        return try {
            val raw = access.read(path, AttachmentSync.MAX_BLOB_BYTES + 1)
            AttachmentSync.checkBlobShape(raw, blobId)
        } catch (e: Exception) {
            null
        }
    }

    /** Names of the blobs in the folder (`[0-9a-f]{64}.lgkblob` only). */
    private fun folderBlobIds(): Set<String> {
        val names = try {
            access.list(FolderLayout.ATTACHMENTS_DIR)
        } catch (e: Exception) {
            return emptySet()
        }
        val suffix = AttachmentSync.BLOB_SUFFIX
        return names.filter { it.endsWith(suffix) }.map { it.dropLast(suffix.length) }.filter { AttachmentSync.isBlobId(it) }.toSet()
    }

    /** Whether [deviceId] published a valid `heir` capability file (sub-plan 08, `.lgkheircap`) when [heir], else the documents one. */
    internal fun folderCapable(gk: GroupKey, deviceId: String, signer: String?, heir: Boolean): Boolean =
        folderCapable(gk, deviceId, signer, if (heir) FeatureCapability.Feature.HEIR else FeatureCapability.Feature.DOCUMENTS)

    /**
     * Whether [deviceId] published a valid capability file for [feature] under [gk], signed by [signer] (desktop
     * `folder_capable` / `collections_capable` / heir). Each feature has its own counter: a file of the other feature copied
     * under this name never counts.
     */
    internal fun folderCapable(
        gk: GroupKey,
        deviceId: String,
        signer: String?,
        feature: FeatureCapability.Feature = FeatureCapability.Feature.DOCUMENTS,
    ): Boolean {
        if (signer == null) return false
        val path = FolderLayout.capabilityFile(deviceId, feature) ?: return false
        val sigPath = FolderLayout.capabilitySignatureFile(deviceId, feature) ?: return false
        return try {
            val raw = access.read(path, AttachmentSync.MAX_CAP_BYTES + 1)
            val sig = access.read(sigPath, ViewSignature.MAX_BYTES + 1)
            FeatureCapability.verify(raw, sig, gk, deviceId, signer, feature)
        } catch (e: Exception) {
            false
        }
    }

    /** The time in [deviceId]'s heartbeat, or null (missing, bad, or not signed by [signer]). */
    internal fun readHeartbeat(gk: GroupKey, deviceId: String, signer: String?): Long? {
        if (signer == null) return null
        val path = FolderLayout.heartbeatFile(deviceId) ?: return null
        val sigPath = FolderLayout.heartbeatSignatureFile(deviceId) ?: return null
        return try {
            val raw = access.read(path, HEARTBEAT_MAX_BYTES + 1)
            val sig = access.read(sigPath, ViewSignature.MAX_BYTES + 1)
            val view = ViewFile.decode(raw, gk, deviceId, maxBytes = HEARTBEAT_MAX_BYTES, maxRecords = 0)
            if (Base64Std.encode(ViewSignature.verify(sig, raw, view.first)) != signer) null else view.first.writtenAt
        } catch (e: Exception) {
            null
        }
    }

    /** Writes this device's heartbeat unless its own valid one is younger than [HEARTBEAT_SECONDS]. */
    private fun writeHeartbeat(gk: GroupKey, state: SyncGroupState, clock: UnixClock) {
        val own = Base64Std.encode(state.identity.signingPublicKey)
        val last = readHeartbeat(gk, state.deviceId, own)
        val age = if (last == null) null else clock.now - last
        if (age != null && age >= 0 && age < HEARTBEAT_SECONDS) return
        val path = FolderLayout.heartbeatFile(state.deviceId) ?: return
        val sigPath = FolderLayout.heartbeatSignatureFile(state.deviceId) ?: return
        val raw = ViewFile.encode(gk, state.deviceId, 0, emptyList(), clock, witnessRandom)
        val sig = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), state.identity)
        access.writeAtomic(path, raw)
        access.writeAtomic(sigPath, sig)
    }

    /** Writes this device's capability file for [feature] unless a valid one is there (a new epoch, damage). */
    private fun writeCapability(
        gk: GroupKey,
        state: SyncGroupState,
        clock: UnixClock,
        feature: FeatureCapability.Feature = FeatureCapability.Feature.DOCUMENTS,
    ) {
        val own = Base64Std.encode(state.identity.signingPublicKey)
        if (folderCapable(gk, state.deviceId, own, feature)) return
        val path = FolderLayout.capabilityFile(state.deviceId, feature) ?: return
        val sigPath = FolderLayout.capabilitySignatureFile(state.deviceId, feature) ?: return
        val (raw, sig) = FeatureCapability.encode(gk, state.identity, feature, clock, witnessRandom)
        access.writeAtomic(path, raw)
        access.writeAtomic(sigPath, sig)
    }

    /** Writes the blob of every own document missing from the folder (before the view is written). */
    private fun publishFolderBlobs(vault: AttachmentVault, own: List<app.localgatekeys.core.engine.ItemState>, now: Long): List<SyncIssue> {
        val out = ArrayList<SyncIssue>()
        val present = folderBlobIds()
        val done = HashSet<String>()
        for (ref in Documents.refs(own)) {
            if (ref.blob in done) continue
            if (ref.blob in present && keepFolderBlob(ref, now)) {
                done.add(ref.blob)
                continue
            }
            val blob = vault.blob(ref)
            if (blob == null) {
                out.add(SyncIssue("attachment-missing", "own:${ref.attachmentId}"))
                continue
            }
            try {
                // Missing, wrong length (a half-synced cloud copy), or old enough that a sweep could take it: (re)write,
                // which also refreshes its time. A failed write does not count as present.
                access.writeAtomic(FolderLayout.blobFile(ref.blob)!!, blob)
                done.add(ref.blob)
            } catch (e: Exception) {
                out.add(SyncIssue("write-failed", "attachment: ${e.message ?: e}"))
            }
        }
        return out
    }

    /**
     * Desktop `BlobFolder.keep`: true when the folder blob has the right length and was written less than half the
     * sweep age ago. False (rewrite it) when its length is wrong or unknown-and-unreadable, or when it is that old or its
     * time is unknown (FolderAccess cannot touch a file's time, so a rewrite refreshes it).
     */
    private fun keepFolderBlob(ref: AttachmentRef, now: Long): Boolean {
        val path = FolderLayout.blobFile(ref.blob) ?: return false
        return try {
            val size = access.size(path) ?: access.read(path, AttachmentSync.MAX_BLOB_BYTES + 1).size.toLong()
            if (size != ref.blobSize) return false
            val at = access.modifiedAt(path) ?: return false
            now - at < AttachmentSync.SWEEP_MIN_AGE_SECONDS / 2
        } catch (e: Exception) {
            false
        }
    }

    /** Removes blobs no view references once older than [AttachmentSync.SWEEP_MIN_AGE_SECONDS] (time unknown: kept). */
    private fun sweepBlobs(referenced: Set<String>, now: Long) {
        for (id in folderBlobIds().sorted()) {
            if (id in referenced) continue
            val path = FolderLayout.blobFile(id) ?: continue
            try {
                val at = access.modifiedAt(path) ?: continue
                if (now - at < AttachmentSync.SWEEP_MIN_AGE_SECONDS) continue
                access.remove(path)
            } catch (e: Exception) {
                // best effort
            }
        }
    }

    /** The own witness file for the view at [counter] and its signature. */
    private fun witnessPair(
        gk: GroupKey,
        state: SyncGroupState,
        counter: Long,
        generation: Long,
        witness: Map<String, Long>,
        clock: UnixClock,
        random: RandomSource,
    ): Pair<ByteArray, ByteArray> {
        val raw = ViewFile.encode(gk, state.deviceId, counter, emptyList(), clock, random, vaultGeneration = generation, witness = witness)
        return raw to ViewSignature.sign(raw, ViewFile.decodeHeader(raw), state.identity)
    }

    private fun writeWitnessPair(deviceId: String, pair: Pair<ByteArray, ByteArray>) {
        val path = FolderLayout.witnessFile(deviceId)
        val sigPath = FolderLayout.witnessSignatureFile(deviceId)
        if (path == null || sigPath == null) throw FolderSyncException("write-failed", "device id is not a safe file name")
        access.writeAtomic(path, pair.first)
        access.writeAtomic(sigPath, pair.second)
    }

    // ---- join and attach ----

    /**
     * Join the group in the folder with the sync password and a fresh device identity, then run once.
     *
     * [kept]: what Leave sync kept of this device (design 2026-11-17, rules 3 and 6). Joining that same group from no
     * group reuses it ([keptUse]): the id is listed again with the same keys (its entry rewritten in place, so the
     * group keeps one member for it) and the own file's counter and the generation offset continue. A kept identity
     * that may not be reused here joins with a fresh one, as does any other group. The caller drops [kept] after a
     * join of its group either way.
     *
     * Refuses another group than the one this store is in (`different-group`) and a healthy membership of the
     * same group (`already-joined`). A wrong password (`password`) or any refusal leaves store and folder untouched.
     */
    fun join(
        store: ItemStore,
        password: String,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
        kept: KeptIdentity? = null,
    ): RunReport = join(store, deviceName, random, clock, kept) { Keyring.passwordKey(it, password) }

    /** How a join uses a kept identity ([keptUse]). */
    internal enum class KeptUse {
        /** A fresh identity (no kept one, another group, or it may not be reused). */
        NONE,

        /** Listed with the same keys: the entry is rewritten in place. */
        REPLACE,

        /** Not listed: added as a new member under the kept id. */
        ADD,
    }

    /**
     * Rule 6: a kept identity of [ring]'s group is reused unless the folder holds a removal notice for its id (any file
     * under that name: dropping it is always safe) or the keyring lists its id with other keys.
     */
    internal fun keptUse(ring: JsonValue, kept: KeptIdentity?): KeptUse {
        if (kept == null || Keyring.str(Keyring.obj(ring)["group_id"]) != kept.groupId) return KeptUse.NONE
        val notice = Removal.noticePath(kept.deviceId) ?: return KeptUse.NONE
        val removed = try {
            access.exists(notice)
        } catch (e: Exception) {
            true // cannot tell: never reuse an id that may have been removed
        }
        if (removed) return KeptUse.NONE
        val listed = (Keyring.obj(ring)["members"] as? JsonValue.Arr)?.items
            ?.firstOrNull { Keyring.str(Keyring.obj(it)["device_id"]) == kept.deviceId }
            ?: return KeptUse.ADD
        return if (KeyringJoin.sameKeys(listed, kept.identity)) KeptUse.REPLACE else KeptUse.NONE
    }

    /** [join] with the Argon2id step injectable (tests pass a known key). */
    internal fun join(
        store: ItemStore,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
        kept: KeptIdentity? = null,
        passwordKey: (JsonValue) -> ByteArray,
    ): RunReport {
        translate {
            val snapshot = store.load()
            val raw = readKeyringOrNull() ?: throw FolderSyncException("no-group", "no sync group in this folder")
            val ring = Keyring.parse(raw)
            val existing = snapshot.sync
            if (existing != null) {
                if (existing.groupId != Keyring.str(Keyring.obj(ring)["group_id"])) {
                    throw FolderSyncException("different-group", "this vault already syncs with another group")
                }
                if (existing.installId == installId && existing.hasFolder && healthyMember(ring, existing)) {
                    throw FolderSyncException("already-joined", "this vault is already a member")
                }
            }
            // A kept identity only rejoins from no group (a store still in the group has its own identity).
            val use = if (existing == null) keptUse(ring, kept) else KeptUse.NONE
            val identity = if (use == KeptUse.NONE || kept == null) DeviceIdentity.generate(random = random) else kept.identity
            val (newRing, gk) = if (use == KeptUse.REPLACE) {
                KeyringJoin.rejoin(ring, identity, deviceName, random, clock) { passwordKey(ring) }
            } else {
                KeyringJoin.join(ring, identity, deviceName, random, clock) { passwordKey(ring) }
            }
            val written = CanonicalJson.encode(newRing, Dialect.UTF8)
            writeKeyring(written, raw)
            val joined = SyncGroupState(
                groupId = gk.groupId, epoch = gk.epoch, key = gk.key, identity = identity, installId = installId,
                hasFolder = true,
                // Counters seen at another epoch are dropped (see [epochReset]); the new identity signs afresh.
                lastSeen = if (existing?.epoch == gk.epoch) existing.lastSeen else emptyMap(),
                peerDigests = if (existing?.epoch == gk.epoch) existing.peerDigests else emptyMap(),
                membersEpoch = gk.epoch, members = sortedNames(memberIds(newRing)), keyring = written, ownCounter = 0,
            )
            // The kept id continues its own file's counter and its generation, so peers take nothing for a replay.
            val newState = if (use != KeptUse.NONE && kept != null) kept.continuing(joined) else joined
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, newState))
            } catch (e: Exception) {
                undoKeyringWrite(written, raw)
                throw e
            }
            if (existing != null && existing.installId == installId) {
                val path = FolderLayout.deviceFile(existing.deviceId)
                val oldFiles = listOf(
                    path, FolderLayout.signatureFile(existing.deviceId), FolderLayout.witnessFile(existing.deviceId),
                    FolderLayout.witnessSignatureFile(existing.deviceId),
                )
                for (old in oldFiles) {
                    if (old == null) continue
                    try {
                        access.remove(old) // our previous identity's file is obsolete
                    } catch (e: Exception) {
                        // best effort
                    }
                }
            }
        }
        return runOnce(store, random, clock)
    }

    /** Use the folder another device added to this store's Wi-Fi-only group (desktop `attach_folder`), then run once. */
    fun attach(store: ItemStore, password: String, deviceName: String, random: RandomSource, clock: UnixClock): RunReport =
        attach(store, deviceName, random, clock) { Keyring.passwordKey(it, password) }

    internal fun attach(
        store: ItemStore,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
        passwordKey: (JsonValue) -> ByteArray,
    ): RunReport {
        translate {
            val snapshot = store.load()
            val state = snapshot.sync ?: throw FolderSyncException("not-joined")
            if (state.installId != installId) {
                throw FolderSyncException("rejoin-required", "this vault was joined on another installation")
            }
            if (state.hasFolder) throw FolderSyncException("already-has-folder", "this sync group already uses a cloud folder")
            val raw = readKeyringOrNull() ?: throw FolderSyncException("no-group", "no sync group in this folder")
            val ring = Keyring.parse(raw)
            if (Keyring.str(Keyring.obj(ring)["group_id"]) != state.groupId) {
                throw FolderSyncException("folder-has-other-group", "this folder holds another sync group")
            }
            val pk = passwordKey(ring)
            val newRing = KeyringJoin.attach(ring, state.identity, deviceName, state.groupKey(), random, clock) { pk }
            val written: ByteArray
            if (newRing == ring) {
                written = raw
            } else {
                written = CanonicalJson.encode(newRing, Dialect.UTF8)
                writeKeyring(written, raw)
            }
            val newState = state.copy(
                hasFolder = true, membersEpoch = state.epoch, members = sortedNames(memberIds(newRing)), keyring = written,
            )
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, newState))
            } catch (e: Exception) {
                if (written !== raw) undoKeyringWrite(written, raw)
                throw e
            }
        }
        return runOnce(store, random, clock)
    }

    // ---- create ----

    /**
     * Start a new group in this folder with this vault as its first member (fresh identity), then run once (desktop
     * `create_folder_group`, Swift `FolderSync.create`). Refuses a vault already in a group (`already-joined`), a
     * folder that holds one (`folder-in-use`), and the keyring reasons (`weak-password`, `bad-name`). [strong]: the
     * sync password rule ([Keyring.isStrongSyncPassword]).
     */
    fun create(
        store: ItemStore,
        password: String,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
    ): RunReport = create(store, password, deviceName, random, clock, strong, KeyringRotate.productionKdf)

    internal fun create(
        store: ItemStore,
        password: String,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): RunReport {
        translate {
            val snapshot = store.load()
            if (snapshot.sync != null) throw FolderSyncException("already-joined", "leave the current sync group first")
            if (readKeyringOrNull() != null) {
                throw FolderSyncException("folder-in-use", "this folder already holds a sync group; join it instead")
            }
            val identity = DeviceIdentity.generate(random = random)
            val (ring, gk) = KeyringRotate.create(password, identity, deviceName, random, clock.now, strong, derive)
            val written = CanonicalJson.encode(ring, Dialect.UTF8)
            writeKeyring(written, null)
            val newState = SyncGroupState(
                groupId = gk.groupId, epoch = gk.epoch, key = gk.key, identity = identity, installId = installId,
                hasFolder = true, membersEpoch = gk.epoch, members = listOf(identity.deviceId), keyring = written,
            )
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, newState))
            } catch (e: Exception) {
                try {
                    if (readKeyringOrNull()?.contentEquals(written) == true) access.remove(FolderLayout.KEYRING_PATH)
                } catch (_: Exception) {
                    // best effort
                }
                throw e
            }
        }
        return runOnce(store, random, clock)
    }

    // ---- add a folder to a Wi-Fi group ----

    /**
     * Give this vault's Wi-Fi-only group this folder with a new sync password, then run once (desktop
     * `add_folder_to_group`, Swift `FolderSync.addFolder(toGroup:)`). The keyring is made for the stored group key
     * ([KeyringRotate.createForExistingGroup]), so the paired devices attach with the password; a folder that already
     * holds this group is attached to instead ([attach]).
     *
     * Audit M9: a removed (revoked) Wi-Fi peer still holds the stored key, so without [freshKey] the call is refused
     * (`lan-peer-removed`). With [freshKey] the keyring is made for a NEW random key at epoch + 1 (same group id,
     * `prev_mac` null) and this device moves to it; the other Wi-Fi peers pair again or attach.
     *
     * Refusals (store and folder untouched): `not-joined`, `rejoin-required`, `already-has-folder`,
     * `folder-has-other-group`, `lan-peer-removed`, the keyring reasons (`weak-password`, `bad-name`).
     */
    fun addFolderToGroup(
        store: ItemStore,
        password: String,
        deviceName: String,
        freshKey: Boolean,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
    ): RunReport = addFolderToGroup(store, password, deviceName, freshKey, random, clock, strong, KeyringRotate.productionKdf)

    internal fun addFolderToGroup(
        store: ItemStore,
        password: String,
        deviceName: String,
        freshKey: Boolean,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): RunReport {
        val existing: Boolean = translate {
            val snapshot = store.load()
            val state = snapshot.sync ?: throw FolderSyncException("not-joined")
            if (state.installId != installId) {
                throw FolderSyncException("rejoin-required", "this vault was joined on another installation")
            }
            if (state.hasFolder) throw FolderSyncException("already-has-folder", "this sync group already uses a cloud folder")
            val raw = readKeyringOrNull()
            if (raw != null) {
                if (Keyring.str(Keyring.obj(Keyring.parse(raw))["group_id"]) != state.groupId) {
                    throw FolderSyncException("folder-has-other-group", "this folder holds another sync group")
                }
                return@translate true
            }
            if (state.lanPeers.any { it.revoked } && !freshKey) {
                throw FolderSyncException("lan-peer-removed", "a removed Wi-Fi device still holds this group's key")
            }
            var gk = state.groupKey()
            if (freshKey) gk = Keyring.groupKey(state.groupId, state.epoch + 1, Keyring.draw(random, Keyring.KEY_LEN))
            val ring = KeyringRotate.createForExistingGroup(gk, password, state.identity, deviceName, random, clock.now, strong, derive)
            val written = CanonicalJson.encode(ring, Dialect.UTF8)
            writeKeyring(written, null)
            val base = if (gk.epoch != state.epoch) epochReset(state, gk.epoch, gk.key) else state
            val newState = base.copy(
                hasFolder = true, membersEpoch = gk.epoch, members = listOf(state.deviceId), keyring = written,
            )
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, newState))
            } catch (e: Exception) {
                try {
                    if (readKeyringOrNull()?.contentEquals(written) == true) access.remove(FolderLayout.KEYRING_PATH)
                } catch (_: Exception) {
                    // best effort
                }
                throw e
            }
            false
        }
        if (existing) {
            return attach(store, deviceName, random, clock) { ring ->
                val salt = Keyring.b64(Keyring.obj(Keyring.obj(ring)["kdf"])["salt"], Keyring.KDF_SALT_LEN, "kdf salt")
                derive.derive(password, salt)
            }
        }
        return runOnce(store, random, clock)
    }

    // ---- rotate (remove devices, change the sync password) ----

    /**
     * New group key and sync password (epoch + 1), dropping [remove], and deletes their files; then runs once (desktop
     * `rotate_folder_group`). The new key is wrapped only to this device and the members in [keep] (the members the
     * user saw and confirmed, audit M10); every other keyring member is dropped like [remove], but only the members in
     * [remove] get a signed removal notice (`LocalGateKeys Sync/removed/<id>.lgkremoved`, written after the keyring).
     * [keep] null means the members this device knows at its epoch minus the unconfirmed ones. With no [remove] it
     * changes the sync password. [strong]: the sync password rule ([Keyring.isStrongSyncPassword]).
     *
     * Refusals (store and folder untouched): `not-joined`, `rejoin-required`, `not-member`, `no-group`, the
     * [Keyring.rotate] reasons (`weak-password`, `stale-trust`, `cannot-remove-self`, `password-reused`, the accept
     * reasons), `keyring-changed` (another device wrote the keyring meanwhile; try again).
     */
    fun rotate(
        store: ItemStore,
        newPassword: String,
        remove: List<String>,
        keep: List<String>?,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
    ): RunReport = rotate(store, newPassword, remove, keep, random, clock, strong, KeyringRotate.productionKdf)

    internal fun rotate(
        store: ItemStore,
        newPassword: String,
        remove: List<String>,
        keep: List<String>?,
        random: RandomSource,
        clock: UnixClock,
        strong: (String) -> Boolean,
        derive: KeyringRotate.KeyDerivation,
    ): RunReport {
        translate {
            val snapshot = store.load()
            val state = snapshot.sync ?: throw FolderSyncException("not-joined")
            if (state.installId != installId) {
                throw FolderSyncException("rejoin-required", "this vault was joined on another installation")
            }
            if (!remove.all { Identifier.isValid(it) }) throw FolderSyncException("not-member", "invalid device id")
            val kept: Set<String> = if (keep != null) {
                if (!keep.all { Identifier.isValid(it) }) throw FolderSyncException("not-member", "invalid device id")
                keep.toSet()
            } else {
                // Members added elsewhere and not yet confirmed never receive the new key (audit M10).
                (if (state.membersEpoch == state.epoch) state.members.toSet() else emptySet()) - state.unackedMembers.toSet()
            }
            val raw = readKeyringOrNull() ?: throw FolderSyncException("no-group", "no sync group in this folder")
            val ring = Keyring.parse(raw)
            val ringIds = memberIds(ring)
            // Only members the user chose get a signed removal notice (never the unconfirmed ones below).
            val notify = sortedNames(remove.filter { it in ringIds && it != state.deviceId }.toSet())
            val unconfirmed = sortedNames(ringIds - kept - remove.toSet() - state.deviceId)
            val drop = remove + unconfirmed
            val (newRing, gk) = KeyringRotate.rotate(ring, state.groupKey(), state.identity, newPassword, drop, random, strong, derive)
            val written = CanonicalJson.encode(newRing, Dialect.UTF8)
            writeKeyring(written, raw)
            val newState = epochReset(state, gk.epoch, gk.key).copy(
                membersEpoch = gk.epoch, members = sortedNames(memberIds(newRing)), keyring = written,
                unackedMembers = emptyList(), // every member kept was confirmed
                lanPeers = state.lanPeers.filter { it.deviceId !in drop }, // the removed devices' Wi-Fi entries go too
            )
            try {
                store.commit(StoreChange(snapshot.revision, snapshot.records, snapshot.meta, newState))
            } catch (e: Exception) {
                undoKeyringWrite(written, raw)
                throw e
            }
            for (dev in sortedNames(drop.toSet())) {
                val files = listOf(
                    FolderLayout.deviceFile(dev), FolderLayout.signatureFile(dev), FolderLayout.witnessFile(dev),
                    FolderLayout.witnessSignatureFile(dev),
                )
                for (path in files) {
                    if (path == null) continue
                    try {
                        access.remove(path)
                    } catch (e: Exception) {
                        // best effort (already gone)
                    }
                }
            }
            for (dev in notify) {
                if (Identifier.isSafeDeviceFile(dev)) writeRemovalNotice(state.identity, state.groupId, dev, gk.epoch, clock.now)
            }
        }
        return runOnce(store, random, clock)
    }

    /**
     * Writes the signed notice that [deviceId] was removed at [epoch] (desktop `write_removal_notice`); false if it could
     * not be written. Best effort: the rotation already happened; without the notice the removed device only stops
     * syncing (it is never erased).
     */
    internal fun writeRemovalNotice(identity: DeviceIdentity, groupId: String, deviceId: String, epoch: Long, now: Long): Boolean = try {
        val path = Removal.noticePath(deviceId) ?: throw RemovalException("bad-notice")
        access.writeAtomic(path, Removal.makeNotice(identity, groupId, deviceId, epoch, now))
        true
    } catch (e: Exception) {
        false
    }

    /**
     * The user confirmed [deviceIds] ("These are my devices"; desktop `acknowledge_members`): only those ids stop being
     * unconfirmed, so one that appeared after the user looked stays. Returns how many were confirmed.
     */
    fun acknowledgeMembers(store: ItemStore, deviceIds: Collection<String>): Int = acknowledgeMembers(store, installId, deviceIds)

    private fun healthyMember(ring: JsonValue, state: SyncGroupState): Boolean = try {
        Keyring.accept(ring, state.groupKey(), state.identity)
        state.deviceId in memberIds(ring)
    } catch (e: Exception) {
        false
    }

    /** Best effort: put [previous] back if the folder still holds exactly [written]. */
    private fun undoKeyringWrite(written: ByteArray, previous: ByteArray) {
        try {
            val now = readKeyringBytes()
            if (now.contentEquals(written)) access.writeAtomic(FolderLayout.KEYRING_PATH, previous)
        } catch (e: Exception) {
            // best effort
        }
    }
}
