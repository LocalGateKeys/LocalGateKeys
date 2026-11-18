package app.localgatekeys.android.access

import app.localgatekeys.android.autofill.FillIndex
import app.localgatekeys.android.autofill.login
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.SaveResult
import app.localgatekeys.android.history.CleanUpModel
import app.localgatekeys.android.history.CommitOrigin
import app.localgatekeys.android.history.FeatureSeams
import app.localgatekeys.android.history.HistoryRecorder
import app.localgatekeys.android.history.PhoneProof
import app.localgatekeys.android.trash.InMemoryLocalData
import app.localgatekeys.android.trash.LocalData
import app.localgatekeys.android.trash.PhoneTrash
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.access.AccessRules
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.proof.PrivacyProof
import app.localgatekeys.core.sync.TravelMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Feature pack 2026-11-15: the Android gates and the glue around the shared rules. */
class FeaturePackTest {
    private val clock = object : UnixClock { override val now = 1_800_000_000L }

    private fun withScope(r: JsonValue.Obj, vararg extra: Pair<String, JsonValue>): JsonValue.Obj {
        val scope = (r.fields["scope"] as JsonValue.Obj).fields + extra
        return JsonValue.Obj(r.fields + ("scope" to JsonValue.Obj(scope)))
    }

    private fun withPolicy(r: JsonValue.Obj, vararg p: Pair<String, JsonValue>) = JsonValue.Obj(r.fields + ("policy" to JsonValue.Obj(mapOf(*p))))

    @Test
    fun policy_and_access_gate_every_fill_reveal_and_copy() {
        val plain = login("a", "https://a.example", "u").fields
        assertEquals(AccessGate.Need.NOTHING, AccessGate.fill(AccessGate.effective(plain), unlockedJustNow = false))
        val never = withPolicy(login("b", "https://b.example", "u"), "fill" to s("never")).fields
        assertEquals(AccessGate.Need.REFUSED, AccessGate.fill(AccessGate.effective(never), unlockedJustNow = true))
        val strict = withPolicy(login("c", "https://c.example", "u"), "require_master_password" to JsonValue.Bool(true)).fields
        assertEquals(AccessGate.Need.OWNER, AccessGate.fill(AccessGate.effective(strict), unlockedJustNow = false))
        assertEquals("the fill's own unlock counts", AccessGate.Need.NOTHING, AccessGate.fill(AccessGate.effective(strict), unlockedJustNow = true))
        assertEquals(AccessGate.Need.OWNER, AccessGate.reveal(AccessGate.effective(strict)))
        val view = withScope(login("d", "https://d.example", "u"), "access" to rec("phones" to s("view"))).fields
        val e = AccessGate.effective(view)
        assertEquals(AccessGate.Need.REFUSED, AccessGate.copy(e, copiedBefore = false))
        assertEquals(AccessGate.Need.REFUSED, AccessGate.fill(e, unlockedJustNow = true))
        assertEquals(AccessGate.Need.OWNER, AccessGate.reveal(e))
        val once = AccessGate.effective(withScope(login("e", "https://e.example", "u"), "access" to rec("copy" to s("once"))).fields)
        assertEquals(AccessGate.Need.NOTHING, AccessGate.copy(once, copiedBefore = false))
        assertEquals(AccessGate.Need.OWNER, AccessGate.copy(once, copiedBefore = true))
        // Unknown key: strictest.
        val unknown = AccessGate.effective(withScope(login("f", "https://f.example", "u"), "access" to rec("zzz" to s("1"))).fields)
        assertTrue(unknown.unknownRule)
        assertEquals(AccessGate.Need.REFUSED, AccessGate.fill(unknown, unlockedJustNow = true))
        // Expired from that day on.
        val dated = withScope(login("g", "https://g.example", "u"), "access" to rec("expires" to s("2026-11-15"))).fields
        assertFalse(AccessGate.effective(dated, "2026-11-14").expired)
        assertTrue(AccessGate.effective(dated, "2026-11-15").expired)
        assertFalse(AccessGate.mayFill(dated, "2026-11-15"))
    }

    @Test
    fun copy_once_ledger_clears_at_lock() {
        val l = CopyOnceLedger()
        assertFalse(l.copiedBefore("x"))
        l.note("x")
        assertTrue(l.copiedBefore("x"))
        l.clear()
        assertFalse(l.copiedBefore("x"))
    }

    @Test
    fun fill_index_leaves_out_never_fill_view_only_and_travel_hidden() {
        val a = login("a", "https://a.example", "u")
        val never = withPolicy(login("b", "https://b.example", "u"), "fill" to s("never"))
        val view = withScope(login("c", "https://c.example", "u"), "access" to rec("phones" to s("view")))
        val tagged = JsonValue.Obj(login("d", "https://d.example", "u").fields + ("tags" to JsonValue.Arr(listOf(s("Bank")))))
        val snap = snapshot(listOf(a, never, view, tagged))
        assertEquals(listOf("a", "d"), FillIndex.build(snap, today = "2026-11-15").entries.map { it.id })
        val travel = TravelMode.Setting(true, emptyList(), listOf("bank"), 5)
        val built = FillIndex.build(snap, mapOf("pkg" to listOf("d", "a")), travel = travel, today = "2026-11-15")
        assertEquals(listOf("a"), built.entries.map { it.id })
        assertEquals("pairings to hidden logins are kept for later", listOf("d", "a"), built.apps["pkg"])
        assertEquals(travel, FillIndex.decode(built.encode())!!.travel)
        assertEquals(TravelMode.Setting.OFF, FillIndex.decode(FillIndex.build(snap).encode())!!.travel)
    }

    @Test
    fun history_restore_that_loosens_an_access_rule_needs_the_owner() {
        val plain = login("a", "https://a.example", "u").fields
        val store = CountingStore(snapshot(listOf(login("a", "https://a.example", "u"))))
        assertEquals(SaveResult.SAVED, AccessRulesModel.save(store, "a", AccessRulesModel.Form(true, false, AccessRules.Settings(phonesView = true), false), true, clock))
        val row = app.localgatekeys.core.history.ItemHistory.Row("s1", "a", "entry", 1, "edit", plain)
        for (path in listOf("scope", "policy")) {
            assertTrue(path, FeatureSeams.restoreLoosens(store, "a", row, path, clock))
            assertEquals(path, SaveResult.FAILED, FeatureSeams.restoreField(store, "a", row, path, clock))
        }
        val rec = ((store.snapshot.records["a"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
        assertTrue("nothing was loosened", AccessGate.effective(rec).phoneView && AccessGate.effective(rec).reauth)
        assertFalse("a plain field needs no owner", FeatureSeams.restoreLoosens(store, "a", row, "username", clock))
        assertEquals(SaveResult.SAVED, FeatureSeams.restoreField(store, "a", row, "policy", clock, ownerConfirmed = true))
    }

    @Test
    fun access_rules_save_needs_pro_to_tighten_never_to_loosen() {
        val store = CountingStore(snapshot(listOf(login("a", "https://a.example", "u"))))
        val tighter = AccessRulesModel.Form(false, false, AccessRules.Settings(copyOnce = true), false)
        assertEquals(SaveResult.NEEDS_PRO, AccessRulesModel.save(store, "a", tighter, isPro = false, clock = clock))
        assertEquals(SaveResult.SAVED, AccessRulesModel.save(store, "a", tighter, isPro = true, clock = clock))
        val rec = ((store.snapshot.records["a"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
        assertEquals(rec("copy" to s("once")), AccessRules.accessOf(rec))
        assertEquals(JsonValue.Int(clock.now), rec["updated_at"])
        val off = AccessRulesModel.Form(false, false, AccessRules.Settings(), false)
        // Loosening never needs Pro but always the owner (scan A-M2): without the check nothing is written.
        assertTrue(AccessRulesModel.needsOwner(store, "a", off))
        assertFalse(AccessRulesModel.needsOwner(store, "a", tighter))
        assertFalse(AccessRulesModel.needsOwner(store, "a", AccessRulesModel.Form(true, false, AccessRules.Settings(copyOnce = true), false)))
        assertEquals(SaveResult.FAILED, AccessRulesModel.save(store, "a", off, isPro = false, clock = clock))
        assertEquals(rec("copy" to s("once")), AccessRules.accessOf(((store.snapshot.records["a"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields))
        val later = AccessRulesModel.Form(false, false, AccessRules.Settings(copyOnce = true, expires = "2030-01-01"), false)
        assertEquals(SaveResult.SAVED, AccessRulesModel.save(store, "a", later, isPro = true, clock = clock))
        assertTrue("a later date loosens", AccessRulesModel.needsOwner(store, "a", later.copy(settings = later.settings.copy(expires = "2031-01-01"))))
        assertTrue("removing the date loosens", AccessRulesModel.needsOwner(store, "a", tighter))
        assertEquals(SaveResult.SAVED, AccessRulesModel.save(store, "a", off, isPro = false, clock = clock, ownerConfirmed = true))
        assertNull(AccessRules.accessOf(((store.snapshot.records["a"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields))
        assertEquals(SaveResult.INVALID, AccessRulesModel.save(store, "a", AccessRulesModel.Form(false, false, AccessRules.Settings(expires = "2026-13-01"), false), true, clock))
    }

    @Test
    fun history_records_replaced_versions_by_origin_and_prunes_by_plan() {
        val local = InMemoryLocalData()
        var pro = false
        var n = 0
        val rec = HistoryRecorder(local, { pro }, clock) { "s${n++}" }
        val before = snapshot(listOf(login("a", "https://a.example", "old"))).records
        val after = snapshot(listOf(login("a", "https://a.example", "new"))).records
        rec.record(before, after)
        CommitOrigin.with("sync") { rec.record(after, before) }
        val rows = rec.rows("a")
        assertEquals(listOf("update", "sync").sorted(), rows.map { it.changeType }.sorted())
        for (i in 0 until 10) rec.record(before, after)
        assertEquals("Free keeps 5", 5, rec.rows("a").size)
        pro = true
        for (i in 0 until 10) rec.record(before, after)
        assertEquals(15, rec.rows("a").size)
        rec.forget("a")
        assertTrue(rec.rows("a").isEmpty())
    }

    @Test
    fun host_store_records_its_commits_as_sync() {
        val inner = CountingStore(snapshot(listOf(login("a", "https://a.example", "u"))))
        var seen: String? = null
        val spy = object : app.localgatekeys.core.sync.ItemStore {
            override fun load() = inner.load()
            override fun commit(change: app.localgatekeys.core.sync.StoreChange) { seen = CommitOrigin.value; inner.commit(change) }
        }
        val host = CommitOrigin.recording("sync", spy)
        val snap = host.load()
        host.commit(app.localgatekeys.core.sync.StoreChange(snap.revision, snap.records, snap.meta, snap.sync))
        assertEquals("sync", seen)
        assertEquals(1, inner.commits)
        assertEquals("update", CommitOrigin.value)
    }

    @Test
    fun history_keeps_at_most_8_mib_dropping_the_oldest_first() {
        val local = InMemoryLocalData()
        var t = 1_800_000_000L
        val moving = object : UnixClock { override val now get() = t }
        var n = 0
        val rec = HistoryRecorder(local, { true }, moving) { "s${n++}" }
        // Each version carries ~1 MiB of notes; 12 edits of 12 items (one version each) pass the cap.
        val big = "x".repeat(1024 * 1024)
        for (k in 0 until 12) {
            val old = JsonValue.Obj(login("i$k", "https://a.example", "old").fields + ("notes" to s(big)))
            val new = JsonValue.Obj(login("i$k", "https://a.example", "new").fields + ("notes" to s(big)))
            rec.record(snapshot(listOf(old)).records, snapshot(listOf(new)).records)
            t += 10
        }
        val rows = local.localData!!.itemHistory
        val bytes = rows.sumOf { app.localgatekeys.core.history.ItemHistory.canon(it).size.toLong() }
        assertTrue(bytes <= 8L * 1024 * 1024)
        assertEquals(7, rows.size)
        val kept = rows.mapNotNull { app.localgatekeys.core.history.ItemHistory.Row.of(it)?.itemId }.toSet()
        assertEquals("the oldest versions went first", (5 until 12).map { "i$it" }.toSet(), kept)
    }

    @Test
    fun passkey_upgrade_shows_for_a_passkey_site_without_a_passkey_and_again_after_90_days() {
        val features = app.localgatekeys.android.security.SiteFeatures(
            mapOf("example.com" to setOf("passkey")), app.localgatekeys.core.records.UrlMatcher(app.localgatekeys.android.autofill.testRules),
        )
        fun item(r: JsonValue.Obj) = app.localgatekeys.android.vault.VaultItem.items(snapshot(listOf(r))).single()
        val l = item(login("a", "https://login.example.com", "u"))
        val up = app.localgatekeys.android.security.PasskeyUpgrade
        assertEquals("example.com", up.domain(l, listOf(l), features))
        assertNull(up.domain(item(login("b", "https://other.test", "u")), listOf(l), features))
        val pk = item(rec("id" to s("p"), "kind" to s("passkey"), "label" to s("K"), "payload" to rec("relying_party_id" to s("example.com"))))
        assertNull("a passkey for the domain exists", up.domain(l, listOf(l, pk), features))
        assertNull(up.domain(l, listOf(l), app.localgatekeys.android.security.SiteFeatures.EMPTY))
        assertTrue(up.shows("example.com", emptyMap(), 100))
        assertFalse(up.shows("example.com", mapOf("example.com" to 100L), 100 + 89L * 86_400))
        assertTrue(up.shows("example.com", mapOf("example.com" to 100L), 100 + 90L * 86_400))
    }

    @Test
    fun travel_mode_change_rules() {
        val off = TravelMode.Setting.OFF
        val on = TravelMode.Setting(true, emptyList(), listOf("Bank"), 9)
        assertEquals(FeatureSeams.TravelCheck.NEEDS_PRO, FeatureSeams.travelCheck(off, on, isPro = false))
        assertEquals(FeatureSeams.TravelCheck.OK, FeatureSeams.travelCheck(off, on, isPro = true))
        assertEquals("turning off never needs Pro, only the owner", FeatureSeams.TravelCheck.OWNER, FeatureSeams.travelCheck(on, off, isPro = false))
        assertEquals(FeatureSeams.TravelCheck.UNCHANGED, FeatureSeams.travelCheck(on, on.copy(since = 99), isPro = false))
        // Narrowing the hidden set while on shows items again: the owner, as for turning off (scan W-M2).
        assertEquals(FeatureSeams.TravelCheck.OWNER, FeatureSeams.travelCheck(on, on.copy(tags = emptyList()), isPro = true))
        assertEquals("a swap is a narrowing", FeatureSeams.TravelCheck.OWNER, FeatureSeams.travelCheck(on, on.copy(tags = listOf("Unused")), isPro = true))
        assertEquals(FeatureSeams.TravelCheck.NEEDS_PRO, FeatureSeams.travelCheck(on, on.copy(tags = listOf("Unused")), isPro = false))
        assertEquals("same tag, other case", FeatureSeams.TravelCheck.OK, FeatureSeams.travelCheck(on, on.copy(tags = listOf("bank"), collections = listOf("c1")), isPro = true))
        val d = LocalData().withTravelMode(on)
        assertEquals(on, LocalData.decode(LocalData.encode(d)).travelMode)
        assertFalse(LocalData().withTravelMode(off).extra.containsKey(LocalData.TRAVEL_MODE))
    }

    @Test
    fun passkey_dismissals_keep_at_most_500() {
        var d = LocalData()
        for (i in 0 until 510) d = d.withPasskeyDismissed("d$i.example", i.toLong())
        assertEquals(500, d.passkeyUpgradeDismissed.size)
        assertFalse(d.passkeyUpgradeDismissed.containsKey("d0.example"))
        assertEquals(509L, LocalData.decode(LocalData.encode(d)).passkeyUpgradeDismissed["d509.example"])
    }

    @Test
    fun clean_up_merges_one_pair_free_and_bulk_needs_pro() {
        val a = JsonValue.Obj(login("a", "https://a.example", "me", "pw", updated = 5).fields)
        val b = JsonValue.Obj(login("b", "https://a.example", "me", "pw", updated = 9).fields)
        val store = CountingStore(snapshot(listOf(a, b)))
        val m = CleanUpModel(store, null, clock, { false }, { it })
        val f = m.findings()
        assertTrue(f.any { it.type == "same_login" && it.ids == listOf("b", "a") })
        assertEquals(CleanUpModel.Result.NeedsPro, m.mergeAllSameLogin())
        assertEquals(CleanUpModel.Result.NeedsPro, m.delete(listOf("a", "b")))
        assertEquals(CleanUpModel.Result.Done, m.merge("b", "a"))
        assertTrue(store.snapshot.meta["a"]?.deleted == true || !store.snapshot.records.containsKey("a"))
    }

    @Test
    fun merge_all_undo_reverts_a_keeper_merged_more_than_once() {
        // Same login three times; each copy has its own note, so every merge changes the keeper (and its digest).
        val a = JsonValue.Obj(login("a", "https://a.example", "me", "pw", updated = 5).fields + ("notes" to s("from a")))
        val b = JsonValue.Obj(login("b", "https://a.example", "me", "pw", updated = 7).fields + ("notes" to s("from b")))
        val c = JsonValue.Obj(login("c", "https://a.example", "me", "pw", updated = 9).fields)
        val store = CountingStore(snapshot(listOf(a, b, c)))
        val before = store.snapshot.records["c"]
        val trash = PhoneTrash(InMemoryLocalData(), store, { true }, clock, EnglishTxt(), null, io = kotlinx.coroutines.Dispatchers.Unconfined)
        val m = CleanUpModel(store, trash, clock, { true }, { it })
        assertEquals(CleanUpModel.Result.Done, m.mergeAllSameLogin())
        assertTrue(store.snapshot.records["c"] != before)
        assertEquals(CleanUpModel.Result.Done, m.undo())
        assertEquals("the keeper is back as it was before the first merge", CleanUpModel.restamped(before!!, clock.now), store.snapshot.records["c"])
        // Stamped now, so other devices take the revert (scan A-L9).
        val back = ((store.snapshot.records["c"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
        assertEquals(JsonValue.Int(clock.now), back["updated_at"])
        assertTrue(store.snapshot.meta["a"]?.deleted != true && store.snapshot.records.containsKey("a"))
        assertTrue(store.snapshot.meta["b"]?.deleted != true && store.snapshot.records.containsKey("b"))
    }

    @Test
    fun a_website_login_merges_with_a_desktop_login_and_keeps_the_stricter_rules() {
        // Scan A-L13: Python allows a web + desktop merge; the phone did not.
        val web = app.localgatekeys.android.vault.webLogin
        val desk = JsonValue.Obj(app.localgatekeys.android.vault.deskLogin.fields + ("scope" to JsonValue.Obj(
            (app.localgatekeys.android.vault.deskLogin.fields["scope"] as JsonValue.Obj).fields + ("access" to JsonValue.Obj(mapOf("phones" to s("view")))),
        )))
        val store = CountingStore(snapshot(listOf(web, desk)))
        val trash = PhoneTrash(InMemoryLocalData(), store, { true }, clock, EnglishTxt(), null, io = kotlinx.coroutines.Dispatchers.Unconfined)
        val m = CleanUpModel(store, trash, clock, { true }, { it })
        assertEquals(CleanUpModel.Result.Done, m.merge("w1", "d1"))
        val kept = ((store.snapshot.records["w1"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields
        val scope = (kept["scope"] as JsonValue.Obj).fields
        assertEquals(s("https://accounts.example.com"), scope["origin"])
        assertEquals("a merge never loosens access rules", JsonValue.Obj(mapOf("phones" to s("view"))), scope["access"])
        assertEquals(listOf("desk-pass"), app.localgatekeys.core.records.PasswordHistory.entries(kept).map { it.password })
        assertEquals(JsonValue.Bool(true), kept["favorite"])
        assertTrue(store.snapshot.meta["d1"]?.deleted == true || !store.snapshot.records.containsKey("d1"))
        // A login and a typed item still refuse.
        val store2 = CountingStore(snapshot(listOf(web, app.localgatekeys.android.vault.note)))
        assertTrue(CleanUpModel(store2, null, clock, { true }, { it }).merge("w1", "n1") != CleanUpModel.Result.Done)
        assertTrue(((store2.snapshot.records["n1"] as JsonValue.Obj).fields["record"] as JsonValue.Obj).fields["kind"] == s("note"))
    }

    @Test
    fun a_merge_whose_other_copy_cannot_be_trashed_puts_the_keeper_back() {
        val a = JsonValue.Obj(login("a", "https://a.example", "me", "pw", updated = 5).fields + ("notes" to s("from a")))
        val c = JsonValue.Obj(login("c", "https://a.example", "me", "pw", updated = 9).fields)
        val store = CountingStore(snapshot(listOf(a, c)))
        val before = store.snapshot.records["c"]!!
        val local = InMemoryLocalData().also { it.failSaves = true }
        val trash = PhoneTrash(local, store, { true }, clock, EnglishTxt(), null, io = kotlinx.coroutines.Dispatchers.Unconfined)
        val m = CleanUpModel(store, trash, clock, { true }, { it })
        assertEquals(CleanUpModel.Result.Failed, m.merge("c", "a"))
        assertEquals(CleanUpModel.restamped(before, clock.now), store.snapshot.records["c"])
        assertTrue(store.snapshot.meta["a"]?.deleted != true && store.snapshot.records.containsKey("a"))
    }

    @Test
    fun travel_dialog_keeps_saved_entries_that_are_not_present_now() {
        val gone = "0b5c0000-0000-4000-8000-000000000001"
        val here = "0b5c0000-0000-4000-8000-000000000002"
        val old = TravelMode.Setting(true, listOf(gone, here), listOf("Bank", "Trip"), 7)
        val shown = app.localgatekeys.android.ui.features.TravelChoice.tags(listOf("bank", "Work"), old)
        assertEquals(listOf("bank", "Work", "Trip"), shown)
        val same = app.localgatekeys.android.ui.features.TravelChoice.setting(true, old, listOf(here), setOf(here), shown, setOf("bank", "trip"), 99)
        assertEquals(setOf(gone, here), same.collections.toSet())
        assertEquals(setOf("bank", "trip"), same.tags.map(TravelMode::fold).toSet())
        assertEquals(7L, same.since)
        assertTrue("nothing narrowed", FeatureSeams.travelCheck(old, same, isPro = true) in setOf(FeatureSeams.TravelCheck.UNCHANGED, FeatureSeams.TravelCheck.OK))
        // Unticking a saved tag still narrows the set (owner's check).
        val narrowed = app.localgatekeys.android.ui.features.TravelChoice.setting(true, old, listOf(here), setOf(here), shown, setOf("bank"), 99)
        assertEquals(FeatureSeams.TravelCheck.OWNER, FeatureSeams.travelCheck(old, narrowed, isPro = true))
    }

    @Test
    fun count_strings_use_plural_forms() {
        val t = EnglishTxt()
        assertEquals("Import undone. 1 item moved to Recently deleted.", t.plural(app.localgatekeys.android.R.plurals.import_undone, 1, 1))
        assertEquals("Import undone. 3 items moved to Recently deleted.", t.plural(app.localgatekeys.android.R.plurals.import_undone, 3, 3))
        assertEquals("1 item changed after the import was kept.", t.plural(app.localgatekeys.android.R.plurals.import_undo_kept_changed, 1, 1))
        assertEquals("1 view-only login was left out.", t.plural(app.localgatekeys.android.R.plurals.access_export_left_out, 1, 1))
        assertEquals("1 hidden item was left out. Turn off travel mode to export it.", t.plural(app.localgatekeys.android.R.plurals.travel_export_left_out, 1, 1))
        assertEquals("Delete 2 items", t.plural(app.localgatekeys.android.R.plurals.hygiene_delete_selected, 2, 2))
        assertEquals(
            "1 duplicate, 2 not changed in 2 years, 0 expired",
            t.s(
                app.localgatekeys.android.R.string.hygiene_summary, t.plural(app.localgatekeys.android.R.plurals.hygiene_summary_duplicates, 1, 1),
                t.plural(app.localgatekeys.android.R.plurals.hygiene_summary_stale, 2, 2), t.plural(app.localgatekeys.android.R.plurals.hygiene_summary_expired, 0, 0),
            ),
        )
    }

    @Test
    fun privacy_proof_counts_visible_items_only() {
        val a = login("a", "https://a.example", "u")
        val tagged = JsonValue.Obj(login("b", "https://b.example", "u").fields + ("tags" to JsonValue.Arr(listOf(s("Bank")))))
        val snap = snapshot(listOf(a, tagged))
        assertEquals(2L, PhoneProof.facts(snap, false, false).items)
        assertEquals(1L, PhoneProof.facts(snap, false, false, TravelMode.Setting(true, emptyList(), listOf("bank"), 5)).items)
    }

    @Test
    fun privacy_proof_is_unsigned_without_sync_and_claims_nothing() {
        val snap = snapshot(listOf(login("a", "https://a.example", "u")))
        val bytes = PhoneProof.build(snap, "0.5.0", breachChecks = true, strictOffline = false)
        assertEquals(PrivacyProof.Status.UNSIGNED, PrivacyProof.verify(bytes).status)
        val text = bytes.toString(Charsets.UTF_8)
        assertTrue(text.contains("\"claims\":[]"))
        assertTrue(text.contains("\"sync\":\"off\""))
        assertNull(PhoneProof.fingerprint(snap))
    }
}
