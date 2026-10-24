package app.localgatekeys.core.support

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.PeerView
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str

/** Shared sync-test data: the epoch-1 group key, the A/B/C device files and identities, the seeded folder. */
object SyncFixtures {
    const val PHONE = "d4444444-0000-4000-8000-00000000000d"
    const val GROUP_ID = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"
    const val T0 = MergeVectors.T0
    const val INSTALL = "android-install-0001"
    const val KEYRING_PATH = "LocalGateKeys Sync/keyring.lgkkeys"

    class Dev(val name: String, val id: String, val counter: Long, val written: Long)

    val devices = listOf(
        Dev("A", MergeVectors.A, 7, 900), Dev("B", MergeVectors.B, 4, 880), Dev("C", MergeVectors.C, 3, 860),
    )

    fun devPath(id: String) = "LocalGateKeys Sync/devices/$id.lgksync"

    fun expected(): Map<String, JsonValue> = Vectors.json(Vectors.sync("expected.json")).obj().fields

    private fun base(existing: Boolean): Map<String, JsonValue> =
        if (existing) obj(expected()["existing_group"]) else expected()

    fun epochKey(e: String, existing: Boolean = false): GroupKey {
        val b = base(existing)
        return GroupKey(str(b["group_id"])!!, e.toLong(), Vectors.hex(str(obj(obj(b["epochs"])[e])["group_key_hex"])!!))
    }

    fun pwKey(e: String, existing: Boolean = false): ByteArray =
        Vectors.hex(str(obj(obj(base(existing)["epochs"])[e])["password_wrap_key_hex"])!!)

    fun identity(who: String): DeviceIdentity {
        val ids = obj(Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"])
        val p = obj(obj(ids[who])["private"])
        return DeviceIdentity(
            str(p["device_id"])!!,
            Base64Std.decodeStrict(str(p["signing_private"])!!),
            Base64Std.decodeStrict(str(p["exchange_private"])!!),
        )
    }

    fun deviceBytes(name: String): ByteArray = Vectors.sync("devices/$name.lgksync").readBytes()

    fun views(): List<PeerView> = devices.map { d ->
        PeerView(d.id, ViewFile.decode(deviceBytes(d.name), epochKey("1"), d.id).second)
    }

    /**
     * The epoch-1 folder with the A/B/C device files. By default as apps from before keyring format 2
     * left it: `keyring_v1_epoch1.json` (members without signing keys) and unsigned views, so
     * first-use pinning applies. [signed]: the format-2 `keyring_epoch1.json` (every member lists its
     * signing key) and each view signed by its device, as current apps write it.
     */
    fun seededFolder(signed: Boolean = false): MemoryFolder {
        val f = MemoryFolder()
        f.files[KEYRING_PATH] = Vectors.sync(if (signed) "keyring_epoch1.json" else "keyring_v1_epoch1.json").readBytes()
        for (d in devices) {
            val raw = deviceBytes(d.name)
            f.files[devPath(d.id)] = raw
            if (signed) {
                f.files[FolderLayout.signatureFile(d.id)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), identity(d.name))
            }
        }
        return f
    }

    fun bridgeStoredStates(): List<ItemState> =
        MergeVectors.arr(MergeVectors.expectedMerge()["bridge_stored_states"]).map(MergeVectors::state)
}
