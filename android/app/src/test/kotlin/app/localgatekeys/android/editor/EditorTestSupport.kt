package app.localgatekeys.android.editor

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.strs
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState

/** The Swift test `MemoryStore`: applies commits like LocalStore (a stale base is refused) and counts them. */
class CountingStore(var snapshot: StoreSnapshot = StoreSnapshot()) : ItemStore {
    var commits = 0
        private set

    override fun load(): StoreSnapshot = snapshot

    override fun commit(change: StoreChange) {
        check(change.baseRevision == snapshot.revision) { "stale" }
        snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
        commits++
    }
}

const val NOW = 1_800_000_000L

fun clock() = TestClock(NOW)

fun editor(
    store: ItemStore,
    item: VaultItem? = null,
    kind: EditorKind = EditorKind.NOTE,
    isPro: () -> Boolean = { false },
    clock: TestClock = clock(),
): EditorModel = EditorModel(store, item, kind, isPro, clock, CountingRandom(), EnglishTxt())

/** Swift `numberedNotes`. */
fun numberedNotes(n: Int): List<Obj> = (0 until n).map { k ->
    rec(
        "id" to s("00000000-0000-4000-8000-%012d".format(k)), "kind" to s("note"), "title" to s("Note $k"),
        "created_at" to i(1_700_000_000), "updated_at" to i(1_700_000_000L + k), "favorite" to Bool(false), "tags" to strs(),
        "payload" to rec("body" to s("body $k"), "fields" to Arr(emptyList()), "template_id" to JsonValue.Null),
    )
}

val validCard: Obj = rec(
    "id" to s("0c000000-0000-4000-8000-000000000001"), "kind" to s("card"), "title" to s("Travel card"),
    "created_at" to i(1_700_000_000), "updated_at" to i(1_700_000_100), "favorite" to Bool(false), "tags" to strs(),
    "payload" to rec("cardholder" to s("A Lovelace"), "number" to s("4111111111111111"), "cvv" to s("123")),
)

const val PHONE_DEVICE = "d4444444-0000-4000-8000-00000000000d"

fun syncState(device: String = PHONE_DEVICE): SyncGroupState = SyncGroupState(
    groupId = "g1", epoch = 1, key = ByteArray(32) { 3 },
    identity = DeviceIdentity(device, ByteArray(32) { 1 }, ByteArray(32) { 2 }),
    installId = "i1", hasFolder = false, membersEpoch = 1,
)

/** Swift `pairedSnapshot`: sync state for this phone and every record live with vv {desk: 3}. */
fun pairedSnapshot(records: List<Obj>): StoreSnapshot {
    val snap = snapshot(records)
    return snap.copy(sync = syncState(), meta = snap.records.mapValues { (_, w) -> SyncMeta.live(w, mapOf("desk" to 3L)) })
}

fun items(store: CountingStore): List<VaultItem> = VaultItem.items(store.snapshot)

/** The stored record of the only (or first) item. */
fun storedRecord(store: CountingStore): Map<String, JsonValue> =
    ((store.snapshot.records.values.first() as Obj).fields["record"] as Obj).fields
