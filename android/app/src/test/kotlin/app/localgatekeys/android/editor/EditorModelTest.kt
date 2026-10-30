package app.localgatekeys.android.editor

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.detail.ItemDetailModel
import app.localgatekeys.android.detail.passkeyItem
import app.localgatekeys.android.pro.ItemLimit
import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.unlock.tempDir
import app.localgatekeys.android.vault.LocalStore
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.card
import app.localgatekeys.android.vault.deskLogin
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.note
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.strs
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.json.JsonValue.Arr
import app.localgatekeys.core.json.JsonValue.Bool
import app.localgatekeys.core.json.JsonValue.Obj
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of `ios/LocalGateKeysTests/EditorAndLimitTests.swift` and the editor half of `MinorFixesTests.swift`, plus the
 * Android-only lock and toString checks. Pro is the `isPro` lambda (ProModel and its purchases land with Task 13).
 */
class EditorModelTest {
    private val clock = clock()

    private fun ed(store: CountingStore, item: VaultItem? = null, kind: EditorKind = EditorKind.NOTE, isPro: () -> Boolean = { false }) =
        editor(store, item, kind, isPro, clock)

    private fun encoded(s: StoreSnapshot): Map<String, String> =
        s.records.mapValues { String(CanonicalJson.encode(it.value, Dialect.UTF8), Charsets.UTF_8) }

    // MARK: limit

    @Test fun over_limit_keeps_items_usable() {
        // Seven synced items on the free plan: everything existing stays editable, deletable and fillable.
        val store = CountingStore(snapshot(numberedNotes(6) + webLogin))
        assertEquals(7, ItemLimit.liveCount(store.snapshot))
        assertFalse(ItemLimit.allows(ItemLimit.Action.CREATE, store.snapshot, isPro = false))
        assertFalse(ItemLimit.allows(ItemLimit.Action.RESTORE, store.snapshot, isPro = false))
        for (a in listOf(ItemLimit.Action.EDIT, ItemLimit.Action.DELETE, ItemLimit.Action.AUTOFILL)) {
            assertTrue(ItemLimit.allows(a, store.snapshot, isPro = false))
        }
        for (item in items(store)) {
            val e = ed(store, item, EditorKind.of(item.kind)!!)
            e.set(e.titleKey, e.value(e.titleKey) + " edited")
            assertEquals("${item.id}: ${e.error}", SaveResult.SAVED, e.save())
            assertFalse(e.showUpgrade)
        }
        assertEquals(7, store.commits)
        assertTrue(items(store).all { it.title.endsWith(" edited") })
        val victim = items(store)[0]
        assertEquals(SaveResult.SAVED, ed(store, victim, EditorKind.of(victim.kind)!!).delete())
        assertEquals(6, ItemLimit.liveCount(store.snapshot))
        // Still over the limit: a new item is refused without writing anything.
        val n = ed(store)
        n.set("title", "Eighth"); n.set("body", "x")
        assertEquals(SaveResult.NEEDS_PRO, n.save())
        assertTrue(n.showUpgrade)
        assertEquals(8, store.commits)
    }

    @Test fun fifth_item_needs_pro() {
        val store = CountingStore(snapshot(numberedNotes(3)))
        var pro = false
        val fourth = ed(store, isPro = { pro })
        fourth.set("title", "Fourth"); fourth.set("body", "b")
        assertEquals(SaveResult.SAVED, fourth.save())
        assertEquals(4, ItemLimit.liveCount(store.snapshot))

        val fifth = ed(store, isPro = { pro })
        fifth.set("title", "Fifth"); fifth.set("body", "b")
        assertEquals(SaveResult.NEEDS_PRO, fifth.save())
        assertTrue(fifth.showUpgrade)
        assertEquals(4, ItemLimit.liveCount(store.snapshot))
        fifth.dismissUpgrade()
        assertFalse(fifth.showUpgrade)

        // Bought (Task 13 provides the purchase): the same editor now saves.
        pro = true
        assertEquals(SaveResult.SAVED, fifth.save())
        assertEquals(5, ItemLimit.liveCount(store.snapshot))
    }

    private val repo = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))

    @Test fun synced_licence_unlocks() {
        val v = CanonicalJson.parse(File(repo, "tests/vectors/sync/license_state.json").readBytes()).obj().fields
        val keys = mapOf(v.getValue("key_id").str() to Base64Std.decodeStrict(v.getValue("public_key_b64").str()))
        val stateId = v.getValue("state_id").str()
        val wrapper = v.getValue("wrapper")
        val store = CountingStore(snapshot(numberedNotes(4), extra = mapOf(stateId to wrapper)))
        // The licence state is not an item and does not use a slot.
        assertEquals(4, ItemLimit.liveCount(store.snapshot))
        assertNull("no licence keys known: the licence cannot verify", ItemLimit.validLicense(store.snapshot, emptyMap()))

        val isPro = { ItemLimit.validLicense(store.snapshot, keys) != null }
        assertTrue(isPro())
        assertEquals("lic-vector-0001", ItemLimit.validLicense(store.snapshot, keys)?.licenseId)
        val fifth = ed(store, isPro = isPro)
        fifth.set("title", "Fifth"); fifth.set("body", "b")
        assertEquals(SaveResult.SAVED, fifth.save())

        // A tampered licence does not unlock.
        val w = wrapper.obj().fields
        val b = w.getValue("record").obj().fields
        val lic = b.getValue("license").obj().fields + ("name" to s("Mallory"))
        val tampered = Obj(w + ("record" to Obj(b + ("license" to Obj(lic)))))
        assertNull(ItemLimit.validLicense(snapshot(numberedNotes(4), extra = mapOf(stateId to tampered)), keys))
    }

    // MARK: editor

    @Test fun unchanged_save_keeps_record_bytes() {
        val store = CountingStore(snapshot(listOf(webLogin, note, card, validCard) + numberedNotes(1)))
        val before = encoded(store.snapshot)
        for (item in items(store)) {
            assertEquals(item.id, SaveResult.UNCHANGED, ed(store, item, EditorKind.of(item.kind)!!).save())
        }
        assertEquals(0, store.commits)
        assertEquals(before, encoded(store.snapshot))
    }

    @Test fun a_changed_login_password_goes_into_the_history() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val item = items(store)[0]
        val old = item.record.getValue("password").str()
        val e = ed(store, item, EditorKind.WEB)
        e.set("password", "Brand-New-Pass-42")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val r = store.snapshot.records.getValue(item.id).obj().fields.getValue("record").obj().fields
        val history = app.localgatekeys.core.records.PasswordHistory.entries(r)
        assertEquals(listOf(old), history.map { it.password })
        assertEquals(NOW, history[0].changedAt)
        // A save that leaves the password alone adds nothing.
        val again = ed(store, items(store)[0], EditorKind.WEB)
        again.set("username", "someone-else")
        assertEquals(SaveResult.SAVED, again.save())
        val r2 = store.snapshot.records.getValue(item.id).obj().fields.getValue("record").obj().fields
        assertEquals(1, app.localgatekeys.core.records.PasswordHistory.entries(r2).size)
    }

    @Test fun edit_restamps_and_normalises_through_lgkcore() {
        val store = CountingStore(snapshot(listOf(validCard)))
        val item = items(store)[0]
        val cid = item.id
        val e = ed(store, item, EditorKind.CARD)
        e.set("number", "4111 1111 1111 1111"); e.set("expiry", "3/2031"); e.set("cvv", "321")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val w = store.snapshot.records.getValue(cid).obj().fields
        val r = w.getValue("record").obj().fields
        val pl = r.getValue("payload").obj().fields
        assertEquals(s("item"), w["ns"])
        assertEquals(i(NOW), r["updated_at"])
        assertEquals(i(NOW), w["updated_at"])
        assertEquals(s("4111111111111111"), pl["number"])
        assertEquals(s("03/31"), pl["expiry"])
        assertEquals(s("1111"), pl["last4"])
        assertEquals(s("visa"), pl["brand"])
        // A bad card number is refused by the normaliser and nothing is written.
        val bad = ed(store, items(store)[0], EditorKind.CARD)
        bad.set("number", "4111111111111112")
        assertEquals(SaveResult.INVALID, bad.save())
        assertNotNull(bad.error)
        assertEquals(1, store.commits)
    }

    @Test fun new_web_login_and_punycode_prompt() {
        val store = CountingStore()
        val e = ed(store, kind = EditorKind.WEB)
        e.set("label", "Shop"); e.set("username", "me"); e.set("password", "pw"); e.set("origin", "https://bücher.example")
        assertEquals(SaveResult.NEEDS_PUNYCODE, e.save())
        assertTrue(e.needsPunycode)
        assertEquals(0, store.commits)
        e.set("origin", "https://xn--bcher-kva.example")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        assertFalse(e.needsPunycode)
        val (id, w) = store.snapshot.records.entries.first()
        val o = w.obj().fields
        val r = o.getValue("record").obj().fields
        val scope = r.getValue("scope").obj().fields
        assertEquals(s("entry"), o["ns"])
        assertEquals(s(id), r["id"])
        assertEquals(s("web"), r["kind"])
        assertEquals(s("https://xn--bcher-kva.example"), scope["origin"])
        assertEquals(i(NOW), r["created_at"])
        assertNotNull(r["policy"])
        assertEquals(36, id.length)
    }

    @Test fun new_identity_and_note() {
        val store = CountingStore()
        val idEditor = ed(store, kind = EditorKind.IDENTITY)
        idEditor.set("title", "Me"); idEditor.set("name", "Ada"); idEditor.set("email", "ada@example.com")
        assertEquals(idEditor.error, SaveResult.SAVED, idEditor.save())
        val n = ed(store, kind = EditorKind.NOTE)
        n.set("title", ""); n.set("body", "x")
        assertEquals("the desktop refuses an empty title", SaveResult.INVALID, n.save())
        assertEquals("Title can't be empty", n.error)
        assertEquals(1, ItemLimit.liveCount(store.snapshot))
        val pl = storedRecord(store).getValue("payload").obj().fields
        assertEquals(s("Ada"), pl["name"])
        assertNull("empty fields the user never filled are not added", pl["phone"])
    }

    @Test fun delete_writes_a_tombstone_through_syncmeta() {
        val base = snapshot(listOf(note, card))
        val snap = base.copy(sync = syncState(), meta = mapOf("n1" to SyncMeta.live(base.records.getValue("n1"), mapOf("desk" to 3L))))
        val store = CountingStore(snap)
        val item = VaultItem.items(snap).first { it.id == "n1" }
        assertEquals(SaveResult.SAVED, ed(store, item, EditorKind.NOTE).delete())
        assertNull(store.snapshot.records["n1"])
        val m = store.snapshot.meta.getValue("n1")
        assertTrue(m.deleted)
        assertEquals(NOW, m.deletedAt)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), m.vv)
        // The sync view sees the same tombstone and does not bump it again.
        val view = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, PHONE_DEVICE, NOW)
        assertEquals(m, view.meta["n1"])
        assertNotNull(store.snapshot.records["c1"])
    }

    @Test fun one_edit_bumps_the_vv_once_and_an_unchanged_save_does_not_restamp() {
        val snap = pairedSnapshot(numberedNotes(1))
        val store = CountingStore(snap)
        val id = snap.records.keys.first()
        // Unchanged save: nothing written, so the sync view keeps the same meta (no new updatedAt, no bump).
        assertEquals(SaveResult.UNCHANGED, ed(store, items(store)[0], EditorKind.NOTE).save())
        val idle = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, PHONE_DEVICE, NOW)
        assertEquals(snap.meta[id], idle.meta[id])
        // One edit: exactly one bump for this device, with the new stamp.
        val e = ed(store, items(store)[0], EditorKind.NOTE)
        e.set("body", "changed")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val first = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, PHONE_DEVICE, NOW)
        val m = first.meta.getValue(id)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), m.vv)
        assertEquals(NOW, m.updatedAt)
        assertNotEquals(snap.meta[id]?.updatedAt, m.updatedAt)
        // A second sync view over the same records does not bump again.
        val second = SyncMeta.localView(store.snapshot.records, first.meta, PHONE_DEVICE, NOW + 5)
        assertEquals(m, second.meta[id])
    }

    @Test fun delete_without_sync_state_never_leaves_a_live_item_behind() {
        // Meta kept after Leave, no sync state: there is no device to bump with, so the editor leaves the meta for
        // `localView`, which tombstones it with exactly one bump on the next join.
        val snap = pairedSnapshot(listOf(note, card)).copy(sync = null)
        val store = CountingStore(snap)
        val item = VaultItem.items(snap).first { it.id == "n1" }
        assertEquals(SaveResult.SAVED, ed(store, item, EditorKind.NOTE).delete())
        assertNull(store.snapshot.records["n1"])
        assertFalse(items(store).any { it.id == "n1" })
        assertEquals(1, ItemLimit.liveCount(store.snapshot))
        val view = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, PHONE_DEVICE, NOW)
        val t = view.meta.getValue("n1")
        assertTrue(t.deleted)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), t.vv)
        assertEquals(true, view.states["n1"]?.deleted)
    }

    /** Swift `test_save_and_delete_commit_inside_a_paired_background_task`: Android has no background task; one commit each. */
    @Test fun save_and_delete_each_commit_once() {
        val store = CountingStore(snapshot(emptyList()))
        val e = ed(store)
        e.set(e.titleKey, "Shopping"); e.set("body", "milk")
        assertEquals(SaveResult.SAVED, e.save())
        assertEquals(1, store.commits)
        val item = items(store).first()
        assertEquals(SaveResult.SAVED, ed(store, item, EditorKind.NOTE).delete())
        assertEquals(2, store.commits)
    }

    /** Review Focus 1: the phone locks while a save is in flight (LocalStore's write gate shuts): nothing is written. */
    @Test fun lock_during_save_writes_nothing() {
        val dir = tempDir("editor-lock")
        val key = ByteArray(32) { 7 }
        val store = LocalStore.open(dir, key, CountingRandom(), null)
        val e = editor(store, null, EditorKind.NOTE, { true }, clock)
        e.set("title", "Locked"); e.set("body", "x")
        store.beginClose()
        assertEquals(SaveResult.FAILED, e.save())
        assertEquals("The item could not be saved on this device.", e.error)
        store.close()
        val reopened = LocalStore.open(dir, key, CountingRandom(), null)
        assertTrue(reopened.load().records.isEmpty())
        // And a delete after lock fails the same way.
        val gated = LocalStore.open(dir, key, CountingRandom(), null)
        gated.beginClose()
        assertEquals(SaveResult.FAILED, EditorModel.delete("n1", gated, clock))
    }

    @Test fun editor_kind_passkey_is_null() {
        assertTrue("a phone kind (created by AutoFill)", "passkey" in Normalise.phoneItemKinds)
        assertNull("but never edited field by field", EditorKind.of("passkey"))
    }

    @Test fun passkey_rename_changes_only_title() {
        val snap = pairedSnapshot(listOf(passkeyItem()))
        val store = CountingStore(snap)
        val id = snap.records.keys.first()
        val item = VaultItem.items(snap)[0]
        // Same title: nothing written.
        assertEquals(SaveResult.UNCHANGED, PasskeyRenameModel(store, item, clock, EnglishTxt()).save())
        assertEquals(0, store.commits)
        val m = PasskeyRenameModel(store, item, clock, EnglishTxt())
        m.setTitle("Work account")
        assertEquals(m.error, SaveResult.SAVED, m.save())
        assertEquals(1, store.commits)
        val beforeW = snap.records.getValue(id).obj().fields
        val afterW = store.snapshot.records.getValue(id).obj().fields
        val before = beforeW.getValue("record").obj().fields
        val after = afterW.getValue("record").obj().fields
        assertEquals(s("Work account"), after["title"])
        assertEquals(i(NOW), after["updated_at"])
        assertEquals(
            "every other field byte-identical",
            String(CanonicalJson.encode(Obj(before - "title" - "updated_at"), Dialect.UTF8)),
            String(CanonicalJson.encode(Obj(after - "title" - "updated_at"), Dialect.UTF8)),
        )
        assertEquals(s("item"), afterW["ns"])
        // Exactly one bump for this device.
        val view = SyncMeta.localView(store.snapshot.records, store.snapshot.meta, PHONE_DEVICE, NOW)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), view.meta[id]?.vv)
        val again = SyncMeta.localView(store.snapshot.records, view.meta, PHONE_DEVICE, NOW + 5)
        assertEquals(view.meta[id], again.meta[id])
        // An empty title is refused (the item keeps its name).
        val empty = PasskeyRenameModel(store, items(store)[0], clock, EnglishTxt())
        empty.setTitle("   ")
        assertEquals(SaveResult.INVALID, empty.save())
        assertEquals("Enter a name.", empty.error)
        assertEquals(1, store.commits)
    }

    @Test fun passkey_delete_tombstones() {
        val snap = pairedSnapshot(listOf(passkeyItem(), note))
        val store = CountingStore(snap)
        val item = VaultItem.items(snap).first { it.kind == "passkey" }
        assertEquals(SaveResult.SAVED, PasskeyRenameModel(store, item, clock, EnglishTxt()).delete())
        assertNull(store.snapshot.records[item.id])
        val m = store.snapshot.meta.getValue(item.id)
        assertTrue(m.deleted)
        assertEquals(NOW, m.deletedAt)
        assertEquals(mapOf("desk" to 3L, PHONE_DEVICE to 1L), m.vv)
        assertNotNull(store.snapshot.records["n1"])
        assertEquals(1, store.commits)
    }

    @Test fun only_phone_kinds_are_editable() {
        val all = VaultItem.items(snapshot(listOf(webLogin, deskLogin, note, card)))
        assertEquals(setOf("w1", "n1", "c1"), all.filter { EditorKind.of(it.kind) != null }.map { it.id }.toSet())
    }

    // MARK: MinorFixesTests (delete of an item already gone; desktop-only kinds)

    @Test fun deleting_an_already_removed_item_says_so() {
        val store = CountingStore(snapshot(listOf(note)))
        val e = ed(store, items(store)[0], EditorKind.NOTE)
        store.snapshot = StoreSnapshot(revision = store.snapshot.revision + 1) // a sync removed it
        assertEquals(SaveResult.UNCHANGED, e.delete())
        assertTrue(e.alreadyRemoved)
        assertEquals("This item was already removed", EnglishTxt().s(EditorScreenText.ALREADY_REMOVED))
        assertNull("not an error: the screen closes after saying so", e.error)
        e.clearAlreadyRemoved()
        assertFalse(e.alreadyRemoved)
    }

    @Test fun deleting_an_already_removed_passkey_says_so() {
        val store = CountingStore(snapshot(listOf(passkeyItem())))
        val m = PasskeyRenameModel(store, items(store)[0], clock, EnglishTxt())
        store.snapshot = StoreSnapshot()
        assertEquals(SaveResult.UNCHANGED, m.delete())
        assertTrue(m.alreadyRemoved)
        m.clearAlreadyRemoved()
        assertFalse(m.alreadyRemoved)
    }

    private fun sshKey(id: String = "55500000-0000-4000-8000-000000000001"): Obj = rec(
        "id" to s(id), "kind" to s("ssh_key"), "title" to s("Server key"),
        "created_at" to i(1_700_000_000), "updated_at" to i(1_700_000_100), "favorite" to Bool(false), "tags" to strs(),
        "payload" to rec("private_key" to s("-----BEGIN OPENSSH PRIVATE KEY-----"), "fields" to Arr(emptyList()), "template_id" to JsonValue.Null),
    )

    @Test fun desktop_only_kinds_offer_delete_only() {
        for (kind in listOf("desktop", "document")) assertTrue(kind, ItemDetailModel.offersDeleteOnly(kind))
        for (kind in listOf(
            "web", "note", "card", "identity", "passkey", "ssh_key", "wifi", "bank_account", "api_key", "license",
            "bookmark", "purchase", "warranty", "subscription",
        )) {
            assertFalse(kind, ItemDetailModel.offersDeleteOnly(kind))
        }
    }

    @Test fun desktop_only_item_delete_writes_a_tombstone() {
        val id = "55500000-0000-4000-8000-000000000001"
        val base = snapshot(listOf(sshKey()))
        val snap = base.copy(
            sync = syncState("phone-1"),
            meta = mapOf(id to SyncMeta.live(base.records.getValue(id), mapOf("desk" to 3L))),
        )
        val store = CountingStore(snap)
        assertEquals(SaveResult.SAVED, EditorModel.delete(id, store, clock))
        assertNull(store.snapshot.records[id])
        val tomb = store.snapshot.meta.getValue(id)
        assertTrue(tomb.deleted)
        assertEquals(1L, tomb.vv["phone-1"])
    }

    // MARK: Android

    @Test fun editor_state_and_model_never_print_values() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val e = ed(store, items(store)[0], EditorKind.WEB)
        e.set("password", "Hunter-2-secret")
        for (text in listOf(e.toString(), e.state.value.toString())) {
            assertFalse(text, text.contains("Hunter-2-secret"))
            assertFalse(text, text.contains("JBSWY3DPEHPK3PXP"))
            assertFalse(text, text.contains("Sample.User"))
        }
        val p = PasskeyRenameModel(CountingStore(snapshot(listOf(passkeyItem()))), VaultItem.items(snapshot(listOf(passkeyItem())))[0], clock, EnglishTxt())
        assertFalse(p.toString().contains("BEGIN"))
    }

    @Test fun errors_name_the_field_the_screen_shows() {
        assertEquals("Title can't be empty", EditorKind.WEB.friendlyError("label cannot be empty", EnglishTxt()))
        assertEquals("Title can't be empty", EditorKind.NOTE.friendlyError("title cannot be empty", EnglishTxt()))
        assertEquals("Website is too long", EditorKind.WEB.friendlyError("origin is too long", EnglishTxt()))
        assertEquals("Title can't be empty", EditorKind.NOTE.friendlyError("item title cannot be empty", EnglishTxt()))
        assertEquals("something else", EditorKind.WEB.friendlyError("something else", EnglishTxt()))
    }
}
