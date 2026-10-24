package app.localgatekeys.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultSearchTest {
    private val items = itemsOf(webLogin, deskLogin, note, card)

    private fun ids(q: String) = VaultSearch.rank(items, q).map { it.id }

    @Test fun empty_query_returns_everything_most_recent_first() {
        assertEquals(listOf("w1", "c1", "n1", "d1"), ids("  "))
    }

    @Test fun search_is_case_insensitive_over_title_username_url_kind_and_tags() {
        assertEquals(listOf("w1"), ids("EXAMPLE ACCOUNT"))
        assertEquals(listOf("w1"), ids("sample.user"))
        assertEquals(listOf("w1"), ids("ACCOUNTS.example"))
        assertEquals(listOf("d1"), ids("samplemail.exe"))
        assertEquals(listOf("c1"), ids("payment"))
        assertEquals(listOf("w1"), ids("personal"))
        assertEquals(listOf("n1"), ids("HOME"))
    }

    @Test fun secrets_notes_and_payloads_are_never_searched() {
        assertEquals(emptyList<String>(), ids("Maple-Orbit"))
        assertEquals(emptyList<String>(), ids("rotated"))
        assertEquals(emptyList<String>(), ids("pantry"))
        assertEquals(emptyList<String>(), ids("4111"))
        assertTrue(VaultSearch.rank(items, "4111111111111111").isEmpty())
    }

    @Test fun every_token_must_match() {
        assertEquals(listOf("w1"), ids("example personal"))
        assertEquals(emptyList<String>(), ids("example home"))
    }

    @Test fun prefix_tokens_restrict_one_field() {
        assertEquals(listOf("n1"), ids("tag:home"))
        assertEquals(listOf("d1"), ids("user:mailer"))
        assertEquals(listOf("w1"), ids("url:accounts"))
        assertEquals(listOf("c1"), ids("type:card"))
        assertEquals(ids(""), ids("tag:")) // an empty prefix value is ignored
        assertEquals(emptyList<String>(), ids("foo:bar")) // an unknown prefix stays literal
    }

    @Test fun rank_exact_then_prefix_then_contains() {
        fun n(id: String, title: String, at: Long) = rec("id" to s(id), "kind" to s("note"), "title" to s(title), "updated_at" to i(at))
        val got = VaultSearch.rank(itemsOf(n("a", "my bank", 3), n("b", "bank", 1), n("c", "bank of x", 2)), "Bank").map { it.id }
        assertEquals(listOf("b", "c", "a"), got)
    }

    @Test fun fuzzy_match_like_difflib() {
        assertEquals(listOf("w1"), ids("exmaple")) // close to "example"
        assertEquals(emptyList<String>(), ids("zq")) // too short for fuzzy, no substring hit
        assertEquals(6.0 * 2 / 14, SequenceRatio.ratio("exmaple", "example"), 1e-9)
    }

    @Test fun sequence_ratio_edges() {
        assertEquals(1.0, SequenceRatio.ratio("", ""), 0.0)
        assertEquals(0.0, SequenceRatio.ratio("abc", ""), 0.0)
        assertEquals(1.0, SequenceRatio.ratio("same", "same"), 0.0)
        // difflib.SequenceMatcher(None, "abcd", "bcde").ratio() == 0.75
        assertEquals(0.75, SequenceRatio.ratio("abcd", "bcde"), 1e-9)
        // difflib.SequenceMatcher(None, "private", "pirate").ratio() == 0.7692307692307693
        assertEquals(0.7692307692307693, SequenceRatio.ratio("private", "pirate"), 1e-12)
        // autojunk: with 200+ characters in b, characters that make up more than 1% + 1 are not match anchors
        val b = "a".repeat(199) + "b"
        assertEquals(2.0 * 1 / (1 + 200), SequenceRatio.ratio("b", b), 1e-12)
    }

    @Test fun nfc_and_nfd_are_different_like_python() {
        val nfc = "café"
        val nfd = "café"
        val items = itemsOf(rec("id" to s("u1"), "kind" to s("note"), "title" to s(nfc), "updated_at" to i(1)))
        assertEquals(listOf("u1"), VaultSearch.rank(items, nfc).map { it.id })
        val fields = VaultSearch.fields(items[0])
        assertEquals(VaultSearch.RANK_EXACT, VaultSearch.tokenRank(fields, null, nfc))
        assertNotEquals(VaultSearch.RANK_EXACT, VaultSearch.tokenRank(fields, null, nfd))
        assertFalse(VaultSearch.containsScalars(nfc, "e"))
        assertTrue(VaultSearch.hasPrefixScalars(nfd, "cafe"))
        assertEquals(listOf("na", "ve", "x"), VaultSearch.words("naïve-x"))
        assertEquals("strasse ss é", VaultSearch.casefold("STRASSE ß É"))
    }

    @Test fun a_search_never_matches_half_a_surrogate_pair() {
        val a = "😀" // U+1F600
        val b = "😁" // U+1F601 shares the high surrogate
        assertFalse(VaultSearch.containsScalars(a, "\uD83D"))
        assertFalse(VaultSearch.hasPrefixScalars(a, "\uD83D"))
        assertTrue(VaultSearch.containsScalars("x$a", a))
        assertFalse(VaultSearch.containsScalars(a, b))
    }

    @Test fun type_filters() {
        assertEquals(
            listOf("All types", "Favorites", "Browser", "Desktop", "Note", "Payment card"),
            VaultSearch.filterOptions(items).map { it.label },
        )
        assertEquals(listOf("n1"), VaultSearch.apply(items, "", VaultFilter.Kind("note")).map { it.id })
        assertEquals(listOf("n1", "d1"), VaultSearch.apply(items, "", VaultFilter.Favorites).map { it.id })
        assertEquals(listOf("w1"), VaultSearch.apply(items, "sample", VaultFilter.Kind("web")).map { it.id })
    }

    @Test fun filter_options_order_other_kinds_by_label() {
        fun k(id: String, kind: String) = rec("id" to s(id), "kind" to s(kind), "title" to s(id))
        val got = VaultSearch.filterOptions(itemsOf(k("a", "wifi"), k("b", "api_key"), k("c", "note"), k("d", "desktop")))
        assertEquals(
            listOf("All types", "Favorites", "Desktop", "API key", "Note", "Wi-Fi network"),
            got.map { it.label },
        )
    }

    @Test fun ties_on_rank_and_time_keep_id_order() {
        fun n(id: String) = rec("id" to s(id), "kind" to s("note"), "title" to s("same"), "updated_at" to i(5))
        assertEquals(listOf("a", "b", "c"), VaultSearch.rank(itemsOf(n("c"), n("a"), n("b")), "same").map { it.id })
    }
}
