package app.localgatekeys.android

import android.content.Intent
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.json.JsonValue.Str
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange

/**
 * Debug builds only (this file is not in the release source set): `lgk.debug.demo=true` fills an EMPTY vault with sample
 * items so emulator screenshots have something to show. Never touches a vault that already has records. Every record
 * the phone edits goes through `Normalise.normalForm`, as a real save would, so seeded items edit and save normally;
 * the desktop login (a kind the phone never normalises) is kept as the desktop would send it.
 */
object DemoSeed {
    private fun rec(vararg f: Pair<String, JsonValue>) = Obj(mapOf(*f))
    private fun s(v: String) = Str(v)
    private fun n(v: Long) = JsonValue.Int(v)
    private fun strs(vararg v: String) = Arr(v.map { Str(it) })

    /** "d0000000-0000-4000-8000-0000000000NN". */
    private fun id(k: Int) = "d0000000-0000-4000-8000-%012d".format(k)

    private const val CREATED = 1_789_000_000L

    private val totp = rec("algorithm" to s("SHA1"), "digits" to n(6), "period" to n(30), "secret" to s("JBSWY3DPEHPK3PXP"))

    private fun login(k: Int, kind: String, label: String, user: String, scope: Obj, at: Long, withTotp: Boolean, fav: Boolean = false) =
        rec(
            "id" to s(id(k)), "kind" to s(kind), "label" to s(label), "username" to s(user), "password" to s("demo-password-$k"),
            "scope" to scope, "tags" to strs(), "favorite" to Bool(fav), "created_at" to n(CREATED), "updated_at" to n(at),
            *(if (withTotp) arrayOf("totp" to totp) else emptyArray()),
        )

    private fun item(k: Int, kind: String, title: String, payload: Obj, at: Long, fav: Boolean = false) =
        rec(
            "id" to s(id(k)), "kind" to s(kind), "title" to s(title), "payload" to payload, "tags" to strs(), "favorite" to Bool(fav),
            "created_at" to n(CREATED), "updated_at" to n(at),
        )

    private val records: List<Obj> = listOf(
        login(1, "web", "GitHub", "sam@example.com", rec("origin" to s("https://github.com")), 1_790_000_900, true, fav = true),
        login(2, "web", "Google", "sam.rivera@example.com", rec("origin" to s("https://accounts.google.com")), 1_790_000_800, true),
        login(3, "web", "Netflix", "sam@example.com", rec("origin" to s("https://www.netflix.com")), 1_790_000_700, false),
        login(4, "web", "Dropbox", "sam@example.com", rec("origin" to s("https://www.dropbox.com")), 1_790_000_650, true),
        login(5, "web", "Local blog", "editor", rec("origin" to s("https://blog.example.net")), 1_790_000_600, false),
        login(6, "desktop", "Mail client", "sam", rec("exe_path" to s("C:/Program Files/Mail/mail.exe")), 1_790_000_500, false),
        item(7, "card", "Travel card", rec("number" to s("4000000000026411"), "expiry" to s("08/27")), 1_790_000_450),
        item(8, "note", "Locker code", rec("body" to s("Gym locker 4821")), 1_790_000_400, fav = true),
        item(9, "bank_account", "Savings", rec("bank" to s("Northwind Bank"), "account_number" to s("DE89 3704 0044 0532 0130 00")), 1_790_000_350),
        item(10, "identity", "Passport", rec("name" to s("Sam Rivera")), 1_790_000_300),
        item(11, "wifi", "Home Wi-Fi", rec("ssid" to s("Home"), "password" to s("demo-wifi"), "security" to s("wpa2")), 1_790_000_250),
        item(12, "api_key", "Cloud API", rec("service" to s("cloud.example.com"), "key" to s("demo-key")), 1_790_000_200),
    )

    /** The seed as the store holds it: id to wrapper, phone kinds normalised. */
    internal fun wrapped(): Map<String, JsonValue> = records.associate { r ->
        val kind = (r.fields["kind"] as Str).v
        val ns = if (kind == "web" || kind == "desktop") Namespace.ENTRY else Namespace.ITEM
        val stored = if (kind == "desktop") r else Normalise.normalForm(ns, r)
        (r.fields["id"] as Str).v to Wrapper.make(ns, stored)
    }

    fun seedIfRequested(intent: Intent?, store: ItemStore) {
        if (intent?.getBooleanExtra("lgk.debug.demo", false) != true) return
        val snap = store.load()
        if (snap.records.isNotEmpty()) return
        store.commit(StoreChange(snap.revision, wrapped(), snap.meta, snap.sync))
    }
}
