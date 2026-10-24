package app.localgatekeys.android.backup

import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.strs
import app.localgatekeys.core.backup.BackupHeader
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Wrapper

/** A cheap KDF for tests that write files (the format's minimum memory); production costs only where a test says so. */
val TEST_KDF = mapOf("time_cost" to 1, "memory_cost_kib" to 8192, "parallelism" to 1)

const val OTHER_PHONE = "b2222222-0000-4000-8000-00000000000b"
const val INSTALL_ID = "0123456789abcdef0123456789abcdef"

/** A note record with a chosen id, title and stamp. */
fun noteRecord(id: String, title: String, updatedAt: Long): JsonValue.Obj = rec(
    "id" to s(id), "kind" to s("note"), "title" to s(title), "created_at" to i(1_700_000_000),
    "updated_at" to i(updatedAt), "favorite" to JsonValue.Bool(false), "tags" to strs(),
    "payload" to rec("body" to s("body of $title"), "fields" to JsonValue.Arr(emptyList())),
)

fun noteId(n: Int): String = "00000000-0000-4000-8000-%012d".format(n)

fun wrap(record: JsonValue.Obj): JsonValue {
    val k = (record.fields["kind"] as JsonValue.Str).v
    return Wrapper.make(if (k == "web" || k == "desktop") Namespace.ENTRY else Namespace.ITEM, record)
}

fun live(record: JsonValue.Obj, vv: Map<String, Long>): ItemState =
    ItemState((record.fields["id"] as JsonValue.Str).v, vv, false, null, wrap(record))

fun tomb(id: String, vv: Map<String, Long>, at: Long): ItemState = ItemState(id, vv, true, at, null)

/** A backup as [PhoneBackupFormat.read] returns it (no file, no Argon2). */
fun backupOf(states: List<ItemState>, device: String = OTHER_PHONE): PhoneBackup = PhoneBackup(
    BackupHeader(1_790_000_000, "android", mapOf("name" to "argon2id"), ByteArray(16), ByteArray(12)),
    device, "1.0.0", false, states.sortedBy { it.itemId },
)
