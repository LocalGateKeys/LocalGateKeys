package app.localgatekeys.android.backup

import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UUID5
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.AttachmentVault

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
 *
 * Format 2 (2026-10-29): with [attachments], the sealed blobs of the live documents go into the file (state-id order,
 * up to 160 MiB and 500 files); a document whose file is missing here or does not fit stays in the backup without its
 * file and is counted in [BackupExport.filesLeftOut]. No file included: a format-1 file, as before.
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
    /** The attachment store the document files are read from (sealed blobs, as folder and Wi-Fi sync send them). */
    private val attachments: AttachmentVault? = null,
) {
    fun export(password: String): ByteArray = exportWithFiles(password).bytes

    fun exportWithFiles(password: String): BackupExport {
        val snap = store.load()
        val now = clock.now
        val device = BackupDevice.id(snap, installId)
        val view = SyncMeta.localView(snap.records, snap.meta, device, now)
        if (view.meta != snap.meta) store.commit(StoreChange(snap.revision, snap.records, view.meta, snap.sync))
        val states = view.states.values.toList()
        val vault = attachments
        val selected = if (vault == null) {
            null
        } else {
            PhoneBackupFormat.selectFiles(states, { ref ->
                try {
                    vault.blob(ref)
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: Exception) {
                    null
                }
            })
        }
        val bytes = PhoneBackupFormat.write(
            states, password, device, PLATFORM, appVersion, now, isPro(), random, kdf, files = selected?.files ?: emptyMap(),
        )
        return BackupExport(bytes, selected?.files?.size ?: 0, selected?.leftOut?.size ?: 0)
    }

    override fun toString(): String = "BackupExporter(appVersion=$appVersion)"

    companion object {
        const val PLATFORM = "android"
    }
}

/** An exported backup file and how many document files it carries / left out. toString never shows the bytes. */
class BackupExport(val bytes: ByteArray, val filesIncluded: Int = 0, val filesLeftOut: Int = 0) {
    override fun toString(): String = "BackupExport(size=${bytes.size}, filesIncluded=$filesIncluded, filesLeftOut=$filesLeftOut)"
}
