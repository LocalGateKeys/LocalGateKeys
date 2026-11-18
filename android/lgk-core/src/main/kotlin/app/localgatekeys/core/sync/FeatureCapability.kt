package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock

/**
 * Folder capability files (desktop `attachment_flow`): a signed, zero-record, format-1 view of the current epoch in
 * `LocalGateKeys Sync/attachments/`, one per feature, telling the other members what this device reads. The view
 * counter tells the features apart, so a file copied under the other name never counts:
 *
 * - documents: `<device>.lgkcap` (+ `.lgkcap.lgksig`), counter 0;
 * - personal collections (sub-plan 07 Task 4): `<device>.lgkcol` (+ `.lgkcol.lgksig`), counter 1;
 * - the emergency access plan (sub-plan 08): `<device>.lgkheircap` (+ `.lgkheircap.lgksig`), counter
 *   [AttachmentSync.HEIR_CAP_COUNTER].
 *
 * Vectors: `tests/vectors/share/collections/capability.json`. The phone writes no `.lgkcol` file yet (it has no
 * collections), so desktop peers keep sending it views without collection states.
 */
object FeatureCapability {
    enum class Feature(val suffix: String, val signatureSuffix: String, val counter: Long) {
        DOCUMENTS(AttachmentSync.CAP_SUFFIX, AttachmentSync.CAP_SIG_SUFFIX, 0),
        COLLECTIONS(".lgkcol", ".lgkcol.lgksig", 1),
        HEIR(AttachmentSync.HEIR_CAP_SUFFIX, AttachmentSync.HEIR_CAP_SIG_SUFFIX, AttachmentSync.HEIR_CAP_COUNTER),
    }

    /**
     * Whether [raw] (with signature [sig]) is [deviceId]'s capability file for [feature] under [gk], signed by [signer]
     * (base64 Ed25519; null never counts). Anything malformed is simply "not capable".
     */
    fun verify(raw: ByteArray?, sig: ByteArray?, gk: GroupKey, deviceId: String, signer: String?, feature: Feature): Boolean {
        if (signer == null || raw == null || sig == null) return false
        return try {
            val (header, _) = ViewFile.decode(raw, gk, deviceId, maxBytes = AttachmentSync.MAX_CAP_BYTES, maxRecords = 0)
            header.counter == feature.counter && Base64Std.encode(ViewSignature.verify(sig, raw, header)) == signer
        } catch (e: Exception) {
            false
        }
    }

    /** The capability file and its signature for [identity] under [gk]. */
    fun encode(gk: GroupKey, identity: DeviceIdentity, feature: Feature, clock: UnixClock, random: RandomSource): Pair<ByteArray, ByteArray> {
        val raw = ViewFile.encode(gk, identity.deviceId, feature.counter, emptyList(), clock, random)
        return raw to ViewSignature.sign(raw, ViewFile.decodeHeader(raw), identity)
    }
}
