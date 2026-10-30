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
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Hex
import app.localgatekeys.core.primitives.Identifier
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.Scalars
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
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
) {
    init {
        if (installId.isEmpty() || Scalars.count(installId) > MAX_INSTALL_ID || installId.contains('\u0000')) {
            throw FolderSyncException("bad-install-id", "install id must be a non-empty bounded string")
        }
    }

    companion object {
        const val STALE_AFTER_SECONDS: Long = SyncMeta.TOMBSTONE_MAX_AGE_DAYS * 86400
        const val OWN_REFRESH_SECONDS: Long = 30 * 86400
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
        val now = clock.now
        val snapshot = try {
            store.load()
        } catch (e: Exception) {
            return RunReport(issues = listOf(SyncIssue("local-data", (e.message ?: e.toString()))))
        }
        var state = snapshot.sync ?: return RunReport(issues = listOf(SyncIssue("not-joined")))
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
            return RunReport(issues = trustedRing.issues.ifEmpty { listOf(SyncIssue("keyring-corrupt")) })
        }
        val issues = ArrayList(trustedRing.issues)
        val original = state
        val current = memberIds(ring)
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
        var report = SyncRunner.run(snapshot, peers.views, state.deviceId, now, licenseKeys, knownDevices, present)
        issues.addAll(report.issues)

        // Rollback witnesses (desktop `run_once` step 9).
        val ownGeneration = Witness.generation(snapshot)
        val checked = Witness.check(
            state.deviceId, ownGeneration ?: 0, if (ownGeneration != null) peers.observations else emptyList(),
            memory?.merged(state) ?: state.peerGenerations, state.rollbackSuspected,
        )
        issues.addAll(checked.issues)
        val witnessKeep = (members + pairedKeys.keys) - state.deviceId
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
        val fullOwn = report.ownStates
        if (fullOwn != null) report = report.copy(ownStates = Documents.publishable(fullOwn, documents))
        var newState = state.copy(
            lastSeen = lastSeen, peerDigests = digests, membersEpoch = gk.epoch, members = sortedNames(members),
            keyring = ringBytes, viewSigners = signers, peerGenerations = peerGenerations,
            rollbackSuspected = checked.rollbackSuspected, witnessPeers = witnessPeers, witnessCounters = witnessCounters,
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
        if (needsWrite && own != null && documents && vault != null) issues.addAll(publishFolderBlobs(vault, own, now))
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

    /** Whether [deviceId] published a valid capability file under [gk], signed by [signer] (desktop `folder_capable`). */
    internal fun folderCapable(gk: GroupKey, deviceId: String, signer: String?): Boolean {
        if (signer == null) return false
        val path = FolderLayout.capabilityFile(deviceId) ?: return false
        val sigPath = FolderLayout.capabilitySignatureFile(deviceId) ?: return false
        return try {
            val raw = access.read(path, AttachmentSync.MAX_CAP_BYTES + 1)
            val sig = access.read(sigPath, ViewSignature.MAX_BYTES + 1)
            val view = ViewFile.decode(raw, gk, deviceId, maxBytes = AttachmentSync.MAX_CAP_BYTES, maxRecords = 0)
            Base64Std.encode(ViewSignature.verify(sig, raw, view.first)) == signer
        } catch (e: Exception) {
            false
        }
    }

    /** Writes this device's capability file unless a valid one is there (a new epoch, damage). */
    private fun writeCapability(gk: GroupKey, state: SyncGroupState, clock: UnixClock) {
        val own = Base64Std.encode(state.identity.signingPublicKey)
        if (folderCapable(gk, state.deviceId, own)) return
        val path = FolderLayout.capabilityFile(state.deviceId) ?: return
        val sigPath = FolderLayout.capabilitySignatureFile(state.deviceId) ?: return
        val raw = ViewFile.encode(gk, state.deviceId, 0, emptyList(), clock, witnessRandom)
        val sig = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), state.identity)
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
     * Refuses another group than the one this store is in (`different-group`) and a healthy membership of the
     * same group (`already-joined`). A wrong password (`password`) or any refusal leaves store and folder untouched.
     */
    fun join(store: ItemStore, password: String, deviceName: String, random: RandomSource, clock: UnixClock): RunReport =
        join(store, deviceName, random, clock) { Keyring.passwordKey(it, password) }

    /** [join] with the Argon2id step injectable (tests pass a known key). */
    internal fun join(
        store: ItemStore,
        deviceName: String,
        random: RandomSource,
        clock: UnixClock,
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
            val identity = DeviceIdentity.generate(random = random)
            val (newRing, gk) = KeyringJoin.join(ring, identity, deviceName, random, clock) { passwordKey(ring) }
            val written = CanonicalJson.encode(newRing, Dialect.UTF8)
            writeKeyring(written, raw)
            val newState = SyncGroupState(
                groupId = gk.groupId, epoch = gk.epoch, key = gk.key, identity = identity, installId = installId,
                hasFolder = true,
                // Counters seen at another epoch are dropped (see [epochReset]); the new identity signs afresh.
                lastSeen = if (existing?.epoch == gk.epoch) existing.lastSeen else emptyMap(),
                peerDigests = if (existing?.epoch == gk.epoch) existing.peerDigests else emptyMap(),
                membersEpoch = gk.epoch, members = sortedNames(memberIds(newRing)), keyring = written, ownCounter = 0,
            )
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
