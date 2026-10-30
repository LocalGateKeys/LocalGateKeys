package app.localgatekeys.android.autofill

import app.localgatekeys.android.passkey.PrivilegedBrowsers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FormParserTest {
    private fun edit(id: String, vararg hints: String, inputType: Int = 1, idEntry: String? = null, hint: String? = null) =
        FillNode(id, hints.toList(), inputType, idEntry, hint, isEditable = true)

    private fun html(id: String, vararg attrs: Pair<String, String>) = FillNode(id, html = mapOf(*attrs), isEditable = true)

    @Test
    fun hints_win() {
        val f = FormParser.parse(listOf(edit("u", "username", idEntry = "pwd"), edit("p", "password")))
        assertEquals(listOf("u"), f.usernames)
        assertEquals(listOf("p"), f.passwords)
        assertFalse(f.newPassword)
    }

    @Test
    fun input_type_password_variations() {
        for (t in listOf(0x81, 0x91, 0xe1, 0x12)) {
            assertEquals("type $t", FormParser.Role.PASSWORD, FormParser.role(edit("p", inputType = t)))
        }
        assertEquals(FormParser.Role.USERNAME, FormParser.role(edit("e", inputType = 0x21)))
    }

    @Test
    fun html_autocomplete_and_type() {
        assertEquals(FormParser.Role.NEW_PASSWORD, FormParser.role(html("a", "type" to "password", "autocomplete" to "new-password")))
        assertEquals(FormParser.Role.PASSWORD, FormParser.role(html("a", "type" to "password")))
        assertEquals(FormParser.Role.USERNAME, FormParser.role(html("a", "type" to "text", "autocomplete" to "section-x username")))
        assertEquals(FormParser.Role.USERNAME, FormParser.role(html("a", "type" to "email")))
        assertEquals(FormParser.Role.OTHER, FormParser.role(html("a", "type" to "text", "autocomplete" to "one-time-code")))
        assertEquals(FormParser.Role.OTHER, FormParser.role(html("a", "type" to "checkbox")))
        assertEquals(FormParser.Role.OTHER, FormParser.role(html("a", "type" to "hidden", "name" to "password")))
    }

    @Test
    fun words_in_ids_and_hints() {
        assertEquals(FormParser.Role.PASSWORD, FormParser.role(edit("p", idEntry = "login_passwort")))
        assertEquals(FormParser.Role.PASSWORD, FormParser.role(edit("p", hint = "Mot de passe")))
        assertEquals(FormParser.Role.USERNAME, FormParser.role(edit("u", hint = "E-mail address")))
        assertEquals(FormParser.Role.OTHER, FormParser.role(edit("s", idEntry = "search_box")))
        assertEquals(FormParser.Role.OTHER, FormParser.role(edit("s", hint = "Shipping address")))
    }

    @Test
    fun non_editable_nodes_are_ignored() {
        assertEquals(FormParser.Role.NONE, FormParser.role(FillNode("label", idEntry = "password_label")))
    }

    @Test
    fun lone_password_takes_previous_text_field_as_username() {
        val f = FormParser.parse(listOf(edit("name", idEntry = "field1"), edit("p", inputType = 0x81)))
        assertEquals(listOf("name"), f.usernames)
        assertEquals(listOf("p"), f.passwords)
    }

    @Test
    fun new_password_form() {
        val f = FormParser.parse(listOf(edit("u", "newUsername"), edit("p1", "newPassword"), edit("p2", "newPassword")))
        assertTrue(f.newPassword)
        assertEquals(listOf("p1", "p2"), f.passwords)
    }

    @Test
    fun web_domain_and_scheme_from_first_node_that_has_one() {
        val f = FormParser.parse(
            listOf(FillNode<String>(null, webDomain = " Accounts.Example.com ", webScheme = "HTTPS"), edit("p", "password")),
        )
        assertEquals("accounts.example.com", f.webDomain)
        assertEquals("https", f.webScheme)
        assertTrue(f.toString().contains("web=true"))
        assertFalse(f.toString().contains("example"))
    }

    @Test
    fun empty_form() {
        assertTrue(FormParser.parse(listOf(edit("x", idEntry = "comment"))).isEmpty)
    }
}

class FillTargetTest {
    private val chromeCert = ByteArray(32) { 1 }
    private val otherCert = ByteArray(32) { 2 }
    private val privileged = PrivilegedBrowsers.parse(
        """{"apps":[{"type":"android","info":{"package_name":"com.android.chrome","signatures":[{"build":"release","cert_fingerprint_sha256":"${"01:".repeat(31)}01"}]}}]}""",
    )

    private fun of(pkg: String, domain: String?, scheme: String? = null, cert: ByteArray = chromeCert) =
        FillTarget.of(pkg, listOf(cert), domain, scheme, "app.localgatekeys.android", privileged)

    @Test
    fun browser_page_is_web() {
        assertEquals(FillTarget.Web("https://accounts.example.com", "com.android.chrome"), of("com.android.chrome", "accounts.example.com"))
    }

    @Test
    fun listed_browser_with_wrong_certificate_is_not_trusted() {
        assertNull(of("com.android.chrome", "accounts.example.com", cert = otherCert))
    }

    @Test
    fun browser_not_on_privileged_list_is_never_trusted_by_package_name() {
        // A sideloaded app can take any free package name (e.g. a browser that is not installed): fail closed.
        assertNull(of("org.mozilla.firefox", "example.com", cert = otherCert))
        assertEquals(FillTarget.App("com.kiwibrowser.browser", "02".repeat(32)), of("com.kiwibrowser.browser", "bank.example.com", cert = otherCert))
    }

    @Test
    fun bundled_privileged_list_covers_every_autofill_browser() {
        val text = java.io.File("src/main/assets/privileged_browsers.json").readText()
        val bundled = PrivilegedBrowsers.parse(text)
        assertTrue(bundled.packages.size > 20)
        val missing = FillTarget.BROWSERS - bundled.packages
        assertTrue("not on the privileged list: $missing", missing.isEmpty())
    }

    @Test
    fun app_web_view_domain_is_ignored() {
        assertEquals(FillTarget.App("com.evil.lookalike", "01".repeat(32)), of("com.evil.lookalike", "bank.example.com"))
    }

    @Test
    fun plain_http_only_on_loopback() {
        assertNull(of("com.android.chrome", "example.com", "http"))
        assertEquals(FillTarget.Web("http://127.0.0.1:8080", "com.android.chrome"), of("com.android.chrome", "127.0.0.1:8080", "http"))
        assertNull(of("com.android.chrome", "example.com", "ftp"))
    }

    @Test
    fun never_fills_itself_or_browser_chrome() {
        assertNull(of("app.localgatekeys.android", null))
        assertNull(of("app.localgatekeys.android.debug", null))
        assertNull(of("com.android.chrome", null))
    }
}
