package app.localgatekeys.android.vault

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreSnapshot

/** The records of the Swift VaultSearchTests (same ids, titles and times). */
fun rec(vararg f: Pair<String, JsonValue>): Obj = Obj(mapOf(*f))

fun i(n: Long): JsonValue = JsonValue.Int(n)

fun s(v: String): JsonValue = Str(v)

fun strs(vararg v: String): JsonValue = Arr(v.map { Str(it) })

val webLogin = rec(
    "id" to s("w1"), "kind" to s("web"), "label" to s("Example account"),
    "username" to s("Sample.User@example.com"), "password" to s("Maple-Orbit-7731"),
    "notes" to s("rotated from the desk PC"), "scope" to rec("origin" to s("https://accounts.example.com")),
    "tags" to strs("Personal"), "favorite" to Bool(false), "updated_at" to i(1_790_000_500),
    "totp" to rec("algorithm" to s("SHA1"), "digits" to i(6), "period" to i(30), "secret" to s("JBSWY3DPEHPK3PXP")),
)
val deskLogin = rec(
    "id" to s("d1"), "kind" to s("desktop"), "label" to s("Sample Mail Client"),
    "username" to s("mailer"), "password" to s("desk-pass"),
    "scope" to rec("exe_path" to s("C:/Program Files/SampleMail/samplemail.exe")),
    "tags" to strs(), "favorite" to Bool(true), "updated_at" to i(1_789_000_000),
)
val note = rec(
    "id" to s("n1"), "kind" to s("note"), "title" to s("Wi-Fi at the cabin"),
    "payload" to rec("body" to s("Router behind the pantry door"), "fields" to Arr(emptyList())),
    "tags" to strs("home"), "favorite" to Bool(true), "updated_at" to i(1_789_956_800),
)
val card = rec(
    "id" to s("c1"), "kind" to s("card"), "title" to s("Travel card"),
    "payload" to rec("brand" to s("visa"), "number" to s("4111111111111111"), "cvv" to s("123")),
    "tags" to strs(), "updated_at" to i(1_789_999_950),
)

fun snapshot(records: List<Obj>, extra: Map<String, JsonValue> = emptyMap(), deleted: Set<String> = emptySet()): StoreSnapshot {
    val rs = LinkedHashMap<String, JsonValue>(extra)
    val meta = LinkedHashMap<String, SyncMeta>()
    for (r in records) {
        val id = (r.fields["id"] as Str).v
        val k = (r.fields["kind"] as Str).v
        rs[id] = Wrapper.make(if (k == "web" || k == "desktop") Namespace.ENTRY else Namespace.ITEM, r)
        if (id in deleted) meta[id] = SyncMeta(null, null, null, emptyMap(), true, 1)
    }
    return StoreSnapshot(rs, meta)
}

fun itemsOf(vararg records: Obj, deleted: Set<String> = emptySet()): List<VaultItem> =
    VaultItem.items(snapshot(records.toList(), deleted = deleted))

fun item(kind: String, vararg f: Pair<String, JsonValue>): VaultItem =
    VaultItem.of("x", Obj(mapOf("kind" to Str(kind), *f)))!!
