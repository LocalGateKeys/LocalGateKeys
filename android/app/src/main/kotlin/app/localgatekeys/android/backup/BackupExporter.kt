package app.localgatekeys.android.backup

import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UUID5
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/**
 * The device id a phone backup is written and restored under (desktop `phone_restore.desktop_device_id`): the sync
 * group's when this phone is in one; otherwise a stable id of this installation (a name-based UUID of its install id,
 * so it survives restarts and goes with an erase). Restoring a backup made under the same id is refused.
 */
object BackupDevice {
    private val NAMESPACE = UUID5.make(UUID5.namespaceUrl, "https://localgatekeys.app/android/backup-device")

    fun id(snapshot: StoreSnapshot, installId: () -> String): String =
        snapshot.sync?.deviceId ?: UUID5.make(NAMESPACE, installId()).toString()
}

/**
 * Settings › Backup › Export backup: the `LGKMBAK1` file of this phone's own local view (every item wrapper with its
 * version vector, tombstones and licence states; never the device identity, group key or folder), platform `android`.
 *
 * The vectors the file carries are committed first when the local view bumped any (as a sync run publishes them), so
 * an edit made after the backup always gets a newer vector than the backup's copy. Through the sync coordinator's
 * gated store, a lock refuses that commit (and the export) and nothing is written. Blocking: call it off the main thread.
 * [kdf] null: the production Argon2id costs (4 / 128 MiB / 4); tests pass cheaper ones.
 */
class BackupExporter(
    private val store: ItemStore,
    private val clock: UnixClock,
    private val random: RandomSource,
    private val appVersion: String,
    private val installId: () -> String,
    /** `pro_hint` (informational only: a store purchase is restored from the store). */
    private val isPro: () -> Boolean = { false },
    private val kdf: Map<String, Int>? = null,
) {
    fun export(password: String): ByteArray {
        val snap = store.load()
        val now = clock.now
        val device = BackupDevice.id(snap, installId)
        val view = SyncMeta.localView(snap.records, snap.meta, device, now)
        if (view.meta != snap.meta) store.commit(StoreChange(snap.revision, snap.records, view.meta, snap.sync))
        return PhoneBackupFormat.write(
            view.states.values.toList(), password, device, PLATFORM, appVersion, now, isPro(), random, kdf,
        )
    }

    override fun toString(): String = "BackupExporter(appVersion=$appVersion)"

    companion object {
        const val PLATFORM = "android"
    }
}
