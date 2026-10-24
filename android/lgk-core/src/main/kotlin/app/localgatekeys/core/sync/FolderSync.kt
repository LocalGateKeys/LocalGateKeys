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
     * peer's view signature may carry, ahead of the signer pinned on first use.
     */
    val pairedKeys: Map<String, String> = emptyMap(),
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
            viewSigners = state.viewSigners.filterKeys { it == state.deviceId },
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

    /** Reads every peer file; never throws for a single bad file. */
    private fun readPeers(
        gk: GroupKey,
        ownId: String,
        members: Set<String>,
        lastSeen: Map<String, Long>,
        digests: Map<String, String>,
        now: Long,
        signers: Map<String, String> = emptyMap(),
        pairedKeys: Map<String, String> = emptyMap(),
    ): PeerRead {
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
            val signer = checkSignature(dev, name, raw, view.first, signers, pairedKeys, out.issues)
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
        }
        if (ignored.isNotEmpty()) out.issues.add(ignoredIssue(ignored))
        return out
    }

    private fun readSignature(deviceId: String): ByteArray? {
        val path = FolderLayout.signatureFile(deviceId) ?: return null
        return try {
            access.read(path, ViewSignature.MAX_BYTES + 1)
        } catch (e: Exception) {
            null
        }
    }

    /** The base64 key of a validly signed view, null for an accepted unsigned one, [REFUSED] to skip it. */
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
        if (ownStates == null) return OwnStatus(false, counter, stale, true, selfSigned)
        val needs = view.second != ownStates || counter != state.ownCounter || !selfSigned ||
            writtenAt < now - OWN_REFRESH_SECONDS
        return OwnStatus(needs, counter, stale, true, selfSigned)
    }

    // ---- one run ----

    /** One full folder sync (desktop `run_once`). Never throws: every problem is an issue in the report. */
    fun runOnce(store: ItemStore, random: RandomSource, clock: UnixClock): RunReport {
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
        val peers = readPeers(
            gk, state.deviceId, members, state.lastSeen, state.peerDigests, now,
            signers = state.viewSigners.filterKeys { it != state.deviceId },
            pairedKeys = pairedKeys.filterKeys { it != state.deviceId },
        )
        issues.addAll(peers.issues)
        val knownDevices = members + state.lastSeen.keys + state.deviceId
        var report = SyncRunner.run(snapshot, peers.views, state.deviceId, now, licenseKeys, knownDevices)
        issues.addAll(report.issues)

        val ownKey = Base64Std.encode(state.identity.signingPublicKey)
        var lastSeen = state.lastSeen + peers.seen
        var digests = state.peerDigests + peers.digests
        var signers = state.viewSigners + peers.signers
        if (lastSeen.size > MAX_PEERS_SEEN || digests.size > MAX_PEERS_SEEN || signers.size > MAX_PEERS_SEEN) {
            lastSeen = lastSeen.filterKeys { it in members }
            digests = digests.filterKeys { it in members }
            signers = signers.filterKeys { it in members }
        }
        var newState = state.copy(
            lastSeen = lastSeen, peerDigests = digests, membersEpoch = gk.epoch, members = sortedNames(members),
            keyring = ringBytes, viewSigners = signers,
        )
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
        if (needsWrite && own != null) {
            val path = FolderLayout.deviceFile(state.deviceId)
            val sigPath = FolderLayout.signatureFile(state.deviceId)
            if (path != null && sigPath != null) {
                try {
                    val raw = ViewFile.encode(gk, state.deviceId, counter, own, clock, random)
                    val header = ViewFile.decodeHeader(raw)
                    val sig = ViewSignature.sign(raw, header, state.identity)
                    access.writeAtomic(path, raw)
                    access.writeAtomic(sigPath, sig)
                    wrote = true
                } catch (e: SyncFormatException) {
                    issues.add(SyncIssue("too-large", (e.message ?: e.toString())))
                } catch (e: Exception) {
                    issues.add(SyncIssue("write-failed", (e.message ?: e.toString())))
                }
            } else {
                issues.add(SyncIssue("write-failed", "device id is not a safe file name"))
            }
        }
        report = report.copy(issues = issues, wrote = wrote)
        return report
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
                for (old in listOf(path, FolderLayout.signatureFile(existing.deviceId))) {
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
