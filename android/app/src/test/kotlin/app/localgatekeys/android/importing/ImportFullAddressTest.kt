package app.localgatekeys.android.importing

import app.localgatekeys.android.editor.EditorModel
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.item
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.core.json.JsonValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Imported logins keep the full page address (tester report 2026-10-29): `https://www.abcdef.com/interface/login.aspx`
 * was saved as `https://www.abcdef.com`. Same cases as Windows `tests/test_import_full_url.py`.
 */
class ImportFullAddressTest {
    private fun row(url: String, match: String) = JsonValue.Obj(linkedMapOf("url" to JsonValue.Str(url), "match" to JsonValue.Str(match)))

    @Test fun full_address_is_a_starts_with_row_after_the_exact_origins() {
        val urls = listOf("https://www.abcdef.com/interface/login.aspx")
        val (web, _, _) = ImportReview.webRows(urls)
        assertEquals(listOf("https://www.abcdef.com"), web)
        assertEquals(
            JsonValue.Arr(listOf(row("https://www.abcdef.com", "exact_origin"), row("https://www.abcdef.com/interface/login.aspx", "starts_with"))),
            ImportReview.urlRows(web, ImportReview.webPages(urls, web)),
        )
    }

    @Test fun bare_sites_upgrades_and_loopback_match_windows() {
        val urls = listOf("https://x.example.com/", "abc.example.com", "http://old.example.com/a?b=1#frag", "http://localhost:8080/p")
        val (web, _, upgraded) = ImportReview.webRows(urls)
        assertEquals(true, upgraded)
        assertEquals(listOf("https://old.example.com/a?b=1", "http://localhost:8080/p"), ImportReview.webPages(urls, web))
    }

    @Test fun open_website_uses_the_page_on_the_same_origin() {
        val scope = rec(
            "origin" to s("https://www.abcdef.com"),
            "urls" to JsonValue.Arr(listOf(row("https://www.abcdef.com", "exact_origin"), row("https://www.abcdef.com/interface/login.aspx", "starts_with"))),
        )
        assertEquals("https://www.abcdef.com/interface/login.aspx", item("web", "scope" to scope).openableUrl)
        val other = rec(
            "origin" to s("https://a.example"),
            "urls" to JsonValue.Arr(listOf(row("https://a.example", "exact_origin"), row("https://b.example/x", "starts_with"))),
        )
        assertEquals("https://a.example", item("web", "scope" to other).openableUrl)
        assertNull(VaultItem.pageAddress(null))
    }

    @Test fun changing_the_website_moves_the_rows_of_the_old_site() {
        val rows = listOf(
            row("https://www.abcdef.com", "exact_origin"), row("https://sso.example.com", "exact_origin"),
            row("https://www.abcdef.com/interface/login.aspx", "starts_with"),
        )
        assertEquals(
            JsonValue.Arr(listOf(row("https://new.example.com", "exact_origin"), row("https://sso.example.com", "exact_origin"))),
            EditorModel.movedRows(rows, "https://www.abcdef.com", "https://new.example.com"),
        )
    }
}
