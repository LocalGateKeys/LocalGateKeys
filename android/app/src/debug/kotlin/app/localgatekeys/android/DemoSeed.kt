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

    /** Each login with a code gets its own secret, so the codes row shows different numbers. */
    private fun totp(secret: String) = rec("algorithm" to s("SHA1"), "digits" to n(6), "period" to n(30), "secret" to s(secret))

    private fun login(k: Int, kind: String, label: String, user: String, scope: Obj, at: Long, secret: String?, fav: Boolean = false) =
        rec(
            "id" to s(id(k)), "kind" to s(kind), "label" to s(label), "username" to s(user), "password" to s(PASSWORDS[k] ?: "Demo-$k-Tq8!vR2#mW5zL"),
            "scope" to scope, "tags" to strs(), "favorite" to Bool(fav), "created_at" to n(CREATED), "updated_at" to n(at),
            *(if (secret != null) arrayOf("totp" to totp(secret)) else emptyArray()),
        )

    private fun item(k: Int, kind: String, title: String, payload: Obj, at: Long, fav: Boolean = false) =
        rec(
            "id" to s(id(k)), "kind" to s(kind), "title" to s(title), "payload" to payload, "tags" to strs(), "favorite" to Bool(fav),
            "created_at" to n(CREATED), "updated_at" to n(at),
        )

    private fun web(origin: String) = rec("origin" to s(origin))
    /** A reused pair and a weak one, so the Security tab has something to show (the rest are strong and unique). */
    private val PASSWORDS = mapOf(6 to "Summer2024!", 4 to "Summer2024!", 9 to "netflix1")
    private const val MAIL = "alex.morgan@example.com"

    // The same persona as the desktop screenshot harness (webui/src/screenshot), so the platforms tell one story.
    private val records: List<Obj> = listOf(
        login(1, "web", "GitHub", "alex-morgan-dev", web("https://github.com"), 1_790_000_900, "GEZDGNBVGY3TQOJQ", fav = true),
        login(2, "web", "Google", MAIL, web("https://accounts.google.com"), 1_790_000_880, "MFRGGZDFMZTWQ2LK", fav = true),
        login(3, "web", "PayPal", MAIL, web("https://www.paypal.com"), 1_790_000_860, "NBSWY3DPO5XXE3DE", fav = true),
        login(4, "web", "Dropbox", MAIL, web("https://www.dropbox.com"), 1_790_000_840, "KRUGS4ZANFZSAYJA"),
        login(5, "web", "Notion", MAIL, web("https://www.notion.so"), 1_790_000_820, "ONSWG4TFOQQGC3TE"),
        login(6, "web", "Discord", MAIL, web("https://discord.com"), 1_790_000_800, "MJQXGZJTGIQGK3TD"),
        login(7, "web", "Apple ID", MAIL, web("https://appleid.apple.com"), 1_790_000_780, "OBQXG43XN5ZGIMJS"),
        login(8, "web", "Airbnb", MAIL, web("https://www.airbnb.com"), 1_790_000_760, null),
        login(9, "web", "Netflix", MAIL, web("https://www.netflix.com"), 1_790_000_740, null),
        login(10, "desktop", "Mail client", "alex", rec("exe_path" to s("C:/Program Files/Mail/mail.exe")), 1_790_000_500, null),
        item(11, "card", "Visa card", rec("number" to s("4000000000026411"), "expiry" to s("08/27")), 1_790_000_450),
        item(12, "note", "Locker code", rec("body" to s("Gym locker 4821")), 1_790_000_400),
        item(13, "bank_account", "Savings", rec("bank" to s("Northwind Bank"), "account_number" to s("DE89 3704 0044 0532 0130 00")), 1_790_000_350),
        item(14, "identity", "Alex Morgan", rec("name" to s("Alex Morgan")), 1_790_000_300),
        item(15, "wifi", "Home Wi-Fi", rec("ssid" to s("Morgan-Home"), "password" to s("demo-wifi"), "security" to s("wpa2")), 1_790_000_250),
        item(16, "api_key", "Deploy service token", rec("service" to s("api.example.com"), "key" to s("demo-key")), 1_790_000_200),
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
