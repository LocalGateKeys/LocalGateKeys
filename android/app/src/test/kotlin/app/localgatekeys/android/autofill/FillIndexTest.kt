package app.localgatekeys.android.autofill

import app.localgatekeys.android.unlock.CountingRandom
import app.localgatekeys.android.editor.CountingStore
import app.localgatekeys.android.vault.card
import app.localgatekeys.android.vault.deskLogin
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.PublicSuffixRules
import app.localgatekeys.core.records.UrlMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

internal val testRules: PublicSuffixRules? by lazy {
    val f = File(System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set"), "src/localvault/assets/public_suffix_list.dat")
    PublicSuffixRules.load(f.readText(Charsets.UTF_8))
}

internal fun login(id: String, url: String, user: String, password: String = "pw-$id", match: String? = null, updated: Long = 1) = rec(
    "id" to s(id), "kind" to s("web"), "label" to s("Site $id"), "username" to s(user), "password" to s(password),
    "scope" to if (match == null) rec("origin" to s(url)) else rec("origin" to s(url), "urls" to JsonValue.Arr(listOf(rec("url" to s(url), "match" to s(match))))),
    "updated_at" to i(updated),
)

class FillIndexTest {
    private val matcher = FillMatcher(UrlMatcher(testRules))

    @Test
    fun index_holds_no_secrets() {
        val index = FillIndex.build(snapshot(listOf(webLogin, deskLogin, card)))
        assertEquals(listOf("w1"), index.entries.map { it.id })
        val text = index.encode().toString(Charsets.UTF_8)
        assertTrue(text.contains("Sample.User@example.com"))
        for (secret in listOf("Maple-Orbit-7731", "JBSWY3DPEHPK3PXP", "rotated from", "desk-pass", "4111")) assertFalse(secret, text.contains(secret))
        assertFalse(index.toString().contains("example"))
    }

    @Test
    fun tombstones_left_out_and_pairings_pruned() {
        val s = snapshot(listOf(webLogin, login("w2", "https://b.example.org", "x")), deleted = setOf("w2"))
        val index = FillIndex.build(s, mapOf("com.app" to listOf("w2", "w1"), "com.gone" to listOf("w2")))
        assertEquals(listOf("w1"), index.entries.map { it.id })
        assertEquals(mapOf("com.app" to listOf("w1")), index.apps)
    }

    @Test
    fun encode_decode_round_trip() {
        val index = FillIndex.build(snapshot(listOf(webLogin, login("w2", "https://shop.example.org", "me", match = "base_domain"))))
            .paired("com.shop", "w2").paired("com.shop", "w1").paired("com.shop", "w2")
        assertEquals(listOf("w2", "w1"), index.apps["com.shop"])
        val back = FillIndex.decode(index.encode())!!
        assertEquals(index, back)
        assertNull(FillIndex.decode("{\"v\":2}".toByteArray()))
        assertNull(FillIndex.decode("junk".toByteArray()))
    }

    @Test
    fun web_matching_uses_desktop_rules() {
        val s = snapshot(
            listOf(
                login("a", "https://accounts.example.com", "exact", updated = 1),
                login("b", "https://www.example.com", "base", match = "base_domain", updated = 5),
                login("c", "https://evil-example.com", "other", match = "base_domain"),
                login("d", "https://accounts.example.com", "newer", updated = 9),
            ),
        )
        val index = FillIndex.build(s)
        val got = matcher.match(index, FillTarget.Web("https://accounts.example.com", "com.android.chrome")).map { it.id }
        assertEquals(listOf("d", "a", "b"), got)
        assertTrue(matcher.match(index, FillTarget.Web("https://example.net", "com.android.chrome")).isEmpty())
    }

    @Test
    fun app_matching_uses_pairings_only() {
        val index = FillIndex.build(snapshot(listOf(webLogin)), mapOf(FillTarget.App("com.bank", "aa").pairKey to listOf("w1")))
        assertEquals(listOf("w1"), matcher.match(index, FillTarget.App("com.bank", "aa")).map { it.id })
        assertTrue(matcher.match(index, FillTarget.App("com.example", "aa")).isEmpty())
    }

    @Test
    fun app_pairing_is_bound_to_the_signing_certificate() {
        // The bank app is uninstalled and another app takes its package name: not offered the bank login.
        val index = FillIndex.build(snapshot(listOf(webLogin)), mapOf(FillTarget.App("com.bank", "aa").pairKey to listOf("w1")))
        assertTrue(matcher.match(index, FillTarget.App("com.bank", "bb")).isEmpty())
        assertTrue(matcher.match(index, FillTarget.App("com.bank", "")).isEmpty())
        assertFalse(matcher.recordMatches(webLogin.fields, "w1", FillTarget.App("com.bank", "bb"), index))
    }

    @Test
    fun recheck_after_unlock() {
        val index = FillIndex.build(snapshot(listOf(webLogin)), mapOf(FillTarget.App("com.bank").pairKey to listOf("w1")))
        assertTrue(matcher.recordMatches(webLogin.fields, "w1", FillTarget.Web("https://accounts.example.com", "b"), index))
        assertFalse(matcher.recordMatches(webLogin.fields, "w1", FillTarget.Web("https://other.example.com", "b"), index))
        assertTrue(matcher.recordMatches(webLogin.fields, "w1", FillTarget.App("com.bank"), index))
        assertFalse(matcher.recordMatches(webLogin.fields, "w1", FillTarget.App("com.evil"), index))
    }
}

class SaveDecisionTest {
    private val matcher = FillMatcher(UrlMatcher(testRules))
    private val web = FillTarget.Web("https://accounts.example.com", "com.android.chrome")

    @Test
    fun new_update_unchanged() {
        val s = snapshot(listOf(login("a", "https://accounts.example.com", "Me@Example.com", "old")))
        val idx = FillIndex.build(s)
        assertEquals(SaveDecision.Update("a"), SaveDecision.decide(s, web, " me@example.com", "new", false, matcher, idx))
        assertEquals(SaveDecision.Unchanged("a"), SaveDecision.decide(s, web, "me@example.com", "old", false, matcher, idx))
        assertEquals(SaveDecision.New, SaveDecision.decide(s, web, "someone-else", "x", false, matcher, idx))
        assertEquals(SaveDecision.New, SaveDecision.decide(s, FillTarget.App("com.x"), "me@example.com", "x", false, matcher, idx))
    }

    @Test
    fun free_limit_blocks_new_only() {
        val s = snapshot((1..4).map { login("l$it", "https://s$it.example.com", "u") })
        val idx = FillIndex.build(s)
        val t = FillTarget.Web("https://s1.example.com", "com.android.chrome")
        assertEquals(SaveDecision.NeedsPro, SaveDecision.decide(s, t, "other", "x", false, matcher, idx))
        assertEquals(SaveDecision.New, SaveDecision.decide(s, t, "other", "x", true, matcher, idx))
        assertEquals(SaveDecision.Update("l1"), SaveDecision.decide(s, t, "u", "changed", false, matcher, idx))
    }

    @Test
    fun new_record_is_normal_form_and_commits() {
        val r = SaveDecision.newRecord("https://www.Example.com/login?x=1", "me", "Secret-1", 1_800_000_000, CountingRandom()) as JsonValue.Obj
        assertEquals(s("www.example.com".removePrefix("www.")), r.fields["label"])
        assertEquals(s("https://www.example.com"), (r.fields["scope"] as JsonValue.Obj).fields["origin"])
        assertEquals(s("Secret-1"), r.fields["password"])
        val store = CountingStore(snapshot(emptyList()))
        store.commit(SaveDecision.change(store.load(), r))
        assertEquals(1, store.commits)
        assertNotNull(SaveDecision.recordOf(store.load(), (r.fields["id"] as JsonValue.Str).v))
    }

    @Test
    fun updated_record_keeps_old_password_in_history() {
        val rec = login("a", "https://accounts.example.com", "me", "old").fields
        val r = (SaveDecision.updatedRecord(rec, "new", 1_800_000_000) as JsonValue.Obj).fields
        assertEquals(s("new"), r["password"])
        assertEquals(listOf("old"), app.localgatekeys.core.records.PasswordHistory.entries(r).map { it.password })
        assertEquals(i(1_800_000_000), r["updated_at"])
    }
}
