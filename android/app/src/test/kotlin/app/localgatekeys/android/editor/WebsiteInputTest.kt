package app.localgatekeys.android.editor

import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.JsonValue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/** Port of `ios/LocalGateKeysTests/WebsiteInputTests.swift`: what people type, reduced to the origin the desktop stores. */
class WebsiteInputTest {
    private val clock = clock()

    private fun error(text: String): WebsiteInputError =
        assertThrows(text, WebsiteInputException::class.java) { WebsiteInput.origin(text) }.error

    @Test fun bare_domain_gets_https() {
        assertEquals("https://github.com", WebsiteInput.origin("github.com"))
        assertEquals("https://github.com", WebsiteInput.origin("  GitHub.com \n"))
        assertEquals("https://localhost:3000", WebsiteInput.origin("localhost:3000"))
        assertEquals("https://github.com", WebsiteInput.origin("//github.com"))
    }

    @Test fun url_with_path_query_or_fragment_is_reduced_to_its_origin() {
        assertEquals("https://github.com", WebsiteInput.origin("https://github.com/login?x=1"))
        assertEquals("https://github.com", WebsiteInput.origin("github.com/login#top"))
        assertEquals("https://github.com", WebsiteInput.origin("https://github.com:443/"))
        assertEquals("https://shop.example:8443", WebsiteInput.origin("https://shop.example:8443/a/b"))
        assertEquals("http://localhost:8080", WebsiteInput.origin("http://localhost:8080/admin"))
    }

    @Test fun plain_http_for_a_public_host_follows_canonicalize() {
        // Origin.canonicalize allows plain HTTP only for loopback hosts.
        assertEquals(WebsiteInputError.Invalid(WebsiteInput.HTTP_MESSAGE), error("HTTP://Example.COM:8080/a"))
        assertEquals("https://example.com:8080", WebsiteInput.origin("HTTPS://Example.COM:8080/a"))
    }

    @Test fun not_a_site_has_a_friendly_error() {
        for (bad in listOf("not a site", "https://", "user@github.com", "ftp://github.com", "git hub.com/x", "github.com:99999", "git hub.com", "a\u0007b.com")) {
            assertEquals(bad, WebsiteInputError.Invalid(WebsiteInput.INVALID_MESSAGE), error(bad))
        }
        assertEquals("Enter a website like github.com", WebsiteInput.INVALID_MESSAGE)
    }

    @Test fun empty_website_is_required() {
        for (empty in listOf("", "   ")) assertEquals(WebsiteInputError.Required, error(empty))
    }

    @Test fun non_ascii_host_still_asks_for_punycode() {
        assertEquals(WebsiteInputError.NeedsPunycode, error("bücher.example/x"))
    }

    // MARK: through the editor

    private fun ed(store: CountingStore, item: VaultItem? = null) = editor(store, item, EditorKind.WEB, { false }, clock)

    private fun storedOrigin(store: CountingStore): JsonValue? = storedRecord(store)["scope"]?.obj()?.fields?.get("origin")

    @Test fun editor_saves_a_typed_domain_as_its_origin() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "GitHub"); e.set("username", "me"); e.set("password", "pw")
        e.set("origin", "github.com/login?return_to=x")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        assertEquals(s("https://github.com"), storedOrigin(store))
        assertNull(e.websiteError)
    }

    @Test fun editor_shows_friendly_inline_errors_and_writes_nothing() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "Site")
        assertEquals(SaveResult.INVALID, e.save())
        assertEquals(WebsiteInput.REQUIRED_MESSAGE, e.websiteError)
        assertEquals("Website is required", WebsiteInput.REQUIRED_MESSAGE)
        assertEquals("Check the website.", e.error)
        e.set("origin", "not a site")
        assertNull("editing the field clears its error", e.websiteError)
        assertEquals(SaveResult.INVALID, e.save())
        assertEquals("Enter a website like github.com", e.websiteError)
        assertFalse("never the raw normaliser text", e.error?.contains("Origin") ?: false)
        assertEquals(0, store.commits)
    }

    @Test fun existing_login_still_saves_unchanged() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val e = ed(store, items(store)[0])
        assertEquals(SaveResult.UNCHANGED, e.save())
        assertEquals(0, store.commits)
    }
}
