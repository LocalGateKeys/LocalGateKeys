package app.localgatekeys.android.reminders

import app.localgatekeys.android.trash.LocalDataHosting
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Where the reminder rows are kept ([LocalReminderStore]: the encrypted local data). Rows hold no titles and no secrets. */
interface ReminderStore {
    fun load(): List<Reminder>

    /** Replaces all rows; throws [IOException] when they could not be saved (the old rows stay). */
    fun save(reminders: List<Reminder>)

    /** Changes the rows as one step (a read-modify-write nobody can interleave with). */
    fun update(change: (List<Reminder>) -> List<Reminder>) = save(change(load()))

    /** Deletes everything (Erase vault, Start fresh, device removal); true when nothing is left. */
    fun wipe(): Boolean
}

class MemoryReminderStore(initial: List<Reminder> = emptyList()) : ReminderStore {
    var rows: List<Reminder> = initial
    var failSaves = false
    override fun load(): List<Reminder> = rows
    override fun save(reminders: List<Reminder>) {
        if (failSaves) throw IOException("save failed")
        rows = reminders
    }
    override fun wipe(): Boolean { rows = emptyList(); return true }
}

/**
 * The rows inside this phone's encrypted local data (`LocalData.reminders`, sealed with the vault key like Recently
 * deleted; the iPhone keeps them in its `LocalData` too). Every change holds the local data's lock, the one Recently
 * deleted uses, so neither loses the other's change. While the vault is locked there are no rows and nothing is saved.
 */
class LocalReminderStore(private val local: LocalDataHosting) : ReminderStore {
    override fun load(): List<Reminder> = local.localData?.reminders ?: emptyList()

    override fun save(reminders: List<Reminder>) = synchronized(local) {
        val data = local.localData ?: throw IOException("locked")
        try {
            local.commitLocalData(data.copy(reminders = reminders))
        } catch (e: IOException) {
            throw e
        } catch (e: Exception) {
            throw IOException("reminders not saved")
        }
    }

    override fun update(change: (List<Reminder>) -> List<Reminder>) = synchronized(local) { save(change(load())) }

    /** The rows go with the vault folder on an erase; this empties them in an open vault. */
    override fun wipe(): Boolean = synchronized(local) {
        if (local.localData?.reminders.isNullOrEmpty()) return@synchronized true
        try {
            save(emptyList())
            true
        } catch (e: IOException) {
            false
        }
    }
}

/**
 * The plain row file the first Android build of the reminders kept in `noBackupFilesDir` (before they moved into the
 * encrypted local data). Read once on the next unlock to carry the rows over, then deleted.
 */
object LegacyReminderFile {
    /** The rows of [bytes], or null when it is not a row file. Rows without an id, an item or a real date are dropped. */
    fun decode(bytes: ByteArray): List<Reminder>? = try {
        val root = CanonicalJson.parse(bytes) as? JsonValue.Obj ?: throw IOException("not rows")
        val list = (root.fields["reminders"] as? JsonValue.Arr)?.items ?: throw IOException("not rows")
        list.mapNotNull { v ->
            val f = (v as? JsonValue.Obj)?.fields ?: return@mapNotNull null
            fun str(k: String) = (f[k] as? JsonValue.Str)?.v
            val id = str("id")?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val item = str("item")?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
            val due = str("due")?.takeIf { ReminderDays.dayNumber(it) != null } ?: return@mapNotNull null
            val lead = ((f["lead"] as? JsonValue.Int)?.v ?: 0L).coerceIn(0L, Reminder.MAX_LEAD_DAYS.toLong()).toInt()
            val snooze = str("snooze")?.takeIf { ReminderDays.dayNumber(it) != null } ?: ""
            val notified = str("notified")?.takeIf { ReminderDays.dayNumber(it) != null } ?: ""
            Reminder(id, item, due, lead, Reminder.Status.of(str("status")), snooze, notified)
        }
    } catch (e: Exception) {
        null
    }

    /**
     * Moves the rows of [file] (if any) into [store], skipping ids it already has, then deletes [file]. A file that
     * cannot be read is deleted too (it holds nothing worth keeping); one whose rows could not be saved stays for the
     * next unlock. True when the file is gone.
     */
    fun migrate(file: File, store: ReminderStore): Boolean {
        if (!file.exists()) return true
        val rows = try { decode(file.readBytes()) } catch (e: IOException) { null } ?: emptyList()
        if (rows.isNotEmpty()) {
            try {
                store.update { have ->
                    val ids = have.map { it.id }.toSet()
                    have + rows.filter { it.id !in ids }.distinctBy { it.id }
                }
            } catch (e: IOException) {
                return false
            }
        }
        return file.delete() || !file.exists()
    }
}

/** Small-file helpers shared by the alarm book: one lock per path, and a replace through a temp file. */
internal object ReminderFiles {
    private val locks = HashMap<String, Any>()
    fun lockFor(file: File): Any = synchronized(locks) { locks.getOrPut(file.absoluteFile.path) { Any() } }

    fun writeAtomically(file: File, bytes: ByteArray) {
        file.absoluteFile.parentFile?.mkdirs()
        val tmp = File(file.absoluteFile.parentFile, "." + file.name + ".tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }
}
