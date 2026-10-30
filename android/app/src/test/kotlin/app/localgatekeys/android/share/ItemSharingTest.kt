package app.localgatekeys.android.share

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.editor.NOW
import app.localgatekeys.android.editor.numberedNotes
import app.localgatekeys.android.editor.validCard
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.share.Share
import app.localgatekeys.core.share.ShareException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** UX workstream 9 on Android: seal an item, receive it through the inbox (open once, three wrong codes), save it. */
class ItemSharingTest {
    @get:Rule val tmp = TemporaryFolder()
    private val random = SystemRandomSource()
    private val clock = TestClock(NOW)

    private fun card(): VaultItem = VaultItem.of(validCard.fields.getValue("id").str(), validCard)!!

    private fun inbox() = ShareInbox(tmp.newFolder("inbox"), java.io.File(tmp.root, "opened.json"), clock)

    @Test fun share_and_receive_a_card_as_a_new_item() {
        val out = ItemSharing.prepare(card(), clock, random)
        assertEquals(6, out.code.split(" ").size)
        assertTrue(out.fitsQr)
        assertFalse(out.qrText.contains("4111111111111111")) // nothing in the clear
        val box = inbox()
        val p = box.accept(out.bytes, keepFile = true)
        assertEquals("Android phone", p.header.sender)
        val opened = box.open(p, out.code.uppercase().replace(" ", "-"))
        assertEquals(JsonValue.Str("Travel card"), opened.item.fields["title"])
        assertFalse("favorite" in opened.item.fields)

        val store = CountingStore()
        assertEquals(ItemSharing.SaveOutcome.SAVED, ItemSharing.save(opened, store, isPro = false, clock, random))
        val saved = VaultItem.items(store.snapshot).single()
        assertNotEquals(card().id, saved.id) // a new item, never the sender's id
        assertEquals("card", saved.kind)
        assertEquals(NOW, saved.createdAt)
        box.opened(p)
        assertNull(box.pending.value)
        assertEquals(0, tmp.root.resolve("inbox").listFiles()!!.size)
        // Open once: the same package again is refused.
        val again = box.accept(out.bytes, keepFile = false)
        try {
            box.open(again, out.code); fail()
        } catch (e: ShareException) {
            assertEquals("already-opened", e.reason)
        }
    }

    @Test fun three_wrong_codes_delete_the_package() {
        val out = ItemSharing.prepare(card(), clock, random)
        val box = inbox()
        val p = box.accept(out.bytes, keepFile = true)
        val wrong = Share.generateCode(random).let { if (it == out.code) Share.generateCode(random) else it }
        repeat(3) { n ->
            try {
                box.open(p, wrong); fail()
            } catch (e: ShareException) {
                assertEquals("wrong-code", e.reason)
            }
            assertEquals(n + 1, p.wrongCodes)
        }
        assertNull(box.pending.value)
        assertEquals(0, tmp.root.resolve("inbox").listFiles()!!.size)
        try {
            box.open(p, out.code); fail()
        } catch (e: ShareException) {
            assertEquals("malformed", e.reason)
        }
    }

    @Test fun the_free_limit_holds_and_pro_lifts_it() {
        val out = ItemSharing.prepare(card(), clock, random)
        val opened = Share.open(out.bytes, out.code, NOW)
        val full = CountingStore(snapshot(numberedNotes(4)))
        assertEquals(ItemSharing.SaveOutcome.NEEDS_PRO, ItemSharing.save(opened, full, isPro = false, clock, random))
        assertEquals(0, full.commits)
        assertEquals(ItemSharing.SaveOutcome.SAVED, ItemSharing.save(opened, full, isPro = true, clock, random))
        assertEquals(5, VaultItem.items(full.snapshot).size)
    }

    @Test fun documents_and_passkeys_are_not_offered() {
        val doc = VaultItem.of("d1", JsonValue.Obj(mapOf("kind" to JsonValue.Str("document"), "title" to JsonValue.Str("Passport"))))!!
        val passkey = VaultItem.of("p1", JsonValue.Obj(mapOf("kind" to JsonValue.Str("passkey"), "title" to JsonValue.Str("Key"))))!!
        assertFalse(ItemSharing.canShare(doc))
        assertFalse(ItemSharing.canShare(passkey))
        assertTrue(ItemSharing.canShare(card()))
    }

    @Test fun a_received_file_survives_until_unlock_and_old_ones_are_purged() {
        val out = ItemSharing.prepare(card(), clock, random)
        val dir = tmp.newFolder("inbox")
        ShareInbox(dir, java.io.File(tmp.root, "opened.json"), clock).accept(out.bytes, keepFile = true)
        val later = ShareInbox(dir, java.io.File(tmp.root, "opened.json"), clock)
        later.restore()
        assertNotEquals(null, later.pending.value)
        assertEquals(ItemSharing.previewTitle(later.open(later.pending.value!!, out.code).item, EnglishTxt()), "Travel card")
        // A copy older than a day goes at the next start.
        dir.listFiles()!!.forEach { it.setLastModified((NOW - Share.LIFETIME - 10) * 1000) }
        later.purge()
        assertEquals(0, dir.listFiles()!!.size)
        // Not a package: refused before anything is kept.
        try {
            later.accept("hello".toByteArray(), keepFile = true); fail()
        } catch (e: ShareException) {
            assertEquals("malformed", e.reason)
        }
        assertEquals(0, dir.listFiles()!!.size)
    }

    // ---------------------------------------------------------- every platform's packages (tests/vectors/share/v1.json)
    private val vectors by lazy {
        val repo = java.io.File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"))
        (app.localgatekeys.core.json.CanonicalJson.parse(java.io.File(repo, "tests/vectors/share/v1.json").readBytes()) as JsonValue.Obj).fields
    }

    private fun matches(urls: JsonValue): List<String> =
        (urls as JsonValue.Arr).items.map { ((it as JsonValue.Obj).fields.getValue("match") as JsonValue.Str).v }

    private fun cases(key: String) = (vectors.getValue(key) as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }

    private fun saveVector(case: Map<String, JsonValue>): Pair<ItemSharing.SaveOutcome, CountingStore> {
        val now = (case.getValue("now") as JsonValue.Int).v
        val opened = Share.open((case.getValue("package") as JsonValue.Str).v.toByteArray(), (case.getValue("code") as JsonValue.Str).v, now)
        assertEquals(case.getValue("item"), opened.item)
        val store = CountingStore()
        return ItemSharing.save(opened, store, isPro = true, TestClock(now), random) to store
    }

    @Test fun every_vector_from_windows_and_the_phones_saves_here() {
        for (case in cases("opens")) {
            val name = (case.getValue("name") as JsonValue.Str).v
            val (outcome, store) = saveVector(case)
            if (case.getValue("phone_saves") == JsonValue.Bool(true)) {
                assertEquals(name, ItemSharing.SaveOutcome.SAVED, outcome)
                val saved = VaultItem.items(store.snapshot).single()
                assertEquals(name, (case.getValue("item") as JsonValue.Obj).fields.getValue("kind").str(), saved.kind)
                if (saved.kind == "web") {
                    val urls = (saved.record.getValue("scope") as JsonValue.Obj).fields.getValue("urls")
                    val sent = ((case.getValue("item") as JsonValue.Obj).fields.getValue("scope") as JsonValue.Obj).fields.getValue("urls")
                    assertEquals(matches(sent), matches(urls)) // starts_with and host rows survive
                }
            } else {
                assertEquals(name, ItemSharing.SaveOutcome.INVALID, outcome) // a desktop login: Windows only
            }
        }
    }

    @Test fun display_shape_from_early_builds_is_converted_and_saved() {
        for (case in cases("legacy")) {
            val (outcome, store) = saveVector(case)
            assertEquals(ItemSharing.SaveOutcome.SAVED, outcome)
            val stored = (case.getValue("stored") as JsonValue.Obj).fields
            val saved = VaultItem.items(store.snapshot).single()
            if (saved.kind == "web") {
                val want = stored.getValue("scope") as JsonValue.Obj
                val got = saved.record.getValue("scope") as JsonValue.Obj
                assertEquals(want.fields["origin"], got.fields["origin"])
                assertEquals(matches(want.fields.getValue("urls")), matches(got.fields.getValue("urls")))
            }
        }
    }

    @Test fun three_wrong_codes_burn_the_package_so_it_cannot_come_back() {
        val out = ItemSharing.prepare(card(), clock, random)
        val box = inbox()
        val p = box.accept(out.bytes, keepFile = false)
        val wrong = Share.generateCode(random).let { if (it == out.code) Share.generateCode(random) else it }
        repeat(3) { runCatching { box.open(p, wrong) } }
        val again = box.accept(out.bytes, keepFile = false)
        try {
            box.open(again, out.code); fail()
        } catch (e: ShareException) {
            assertEquals("already-opened", e.reason)
        }
    }
}
