package app.localgatekeys.android.editor

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.pro.ProFeatures
import app.localgatekeys.android.vault.VaultItem
import app.localgatekeys.android.vault.i
import app.localgatekeys.android.vault.rec
import app.localgatekeys.android.vault.s
import app.localgatekeys.android.vault.snapshot
import app.localgatekeys.android.vault.webLogin
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.totp.Totp
import app.localgatekeys.core.totp.TotpException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Port of `ios/LocalGateKeysTests/EditorTOTPAndInputTests.swift`. The credential content type test is
 * `ui/editor/EditorKeyboardTest`; the StoreKit launch test lands with Task 13.
 */
class EditorTotpAndInputTest {
    private val clock = clock()

    /** A Pro phone: adding or changing 2FA codes is a Pro feature (free-plan behaviour is tested below). */
    private fun ed(store: CountingStore, item: VaultItem? = null, isPro: Boolean = true) =
        editor(store, item, EditorKind.WEB, { isPro }, clock)

    // MARK: 2FA on the free plan (Pro-only feature; existing codes are never locked)

    @Test fun free_plan_refuses_a_new_secret_and_writes_nothing() {
        val store = CountingStore()
        val e = ed(store, isPro = false)
        assertTrue(e.totpNeedsPro)
        e.set("label", "Shop"); e.set("origin", "https://shop.example"); e.set("totp", "JBSWY3DPEHPK3PXP")
        assertEquals(SaveResult.NEEDS_PRO, e.save())
        assertTrue(e.showUpgrade)
        assertEquals(ProFeatures.totpMessage(EnglishTxt()), e.totpError)
        assertTrue(e.totpErrorIsPro)
        assertEquals("Two-factor codes need Pro.", e.error)
        assertEquals(0, store.commits)
        e.set("totp", "")
        assertEquals(e.error, SaveResult.SAVED, e.save())
    }

    @Test fun free_plan_keeps_an_existing_secret_through_other_edits_and_can_clear_it() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val e = ed(store, items(store)[0], isPro = false)
        val saved = storedRecord(store)["totp"]
        e.set("label", "Renamed")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        assertEquals(saved, storedRecord(store)["totp"])
        val change = ed(store, items(store)[0], isPro = false)
        change.set("totp", "KRSXG5CTMVRXEZLU")
        assertEquals(SaveResult.NEEDS_PRO, change.save())
        assertEquals(saved, storedRecord(store)["totp"])
        val clear = ed(store, items(store)[0], isPro = false)
        clear.set("totp", "")
        assertEquals(clear.error, SaveResult.SAVED, clear.save())
        assertNull(storedRecord(store)["totp"])
    }

    @Test fun pro_features_rule() {
        val code = rec("secret" to s("JBSWY3DPEHPK3PXP"))
        val other = rec("secret" to s("KRSXG5CTMVRXEZLU"))
        assertTrue(ProFeatures.totpChangeNeedsPro(code, null))
        assertTrue(ProFeatures.totpChangeNeedsPro(other, code))
        assertFalse(ProFeatures.totpChangeNeedsPro(code, code))
        assertFalse(ProFeatures.totpChangeNeedsPro(null, code))
        assertFalse(ProFeatures.totpChangeNeedsPro(JsonValue.Null, code))
    }

    @Test fun new_login_with_base32_secret_stores_the_desktop_shape() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "Shop"); e.set("username", "me"); e.set("password", "pw"); e.set("origin", "https://shop.example")
        e.set("totp", "jbsw y3dp-ehpk 3pxp")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val r = storedRecord(store)
        assertEquals(rec("secret" to s("JBSWY3DPEHPK3PXP"), "algorithm" to s("SHA1"), "digits" to i(6), "period" to i(30)), r["totp"])
        // The record passes the desktop's validation rules (core Normalise mirrors item_schema) unchanged.
        val again = Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(r))
        assertTrue(EditorModel.same(again, JsonValue.Obj(r)))
        // And the detail screen can now produce a code.
        assertNotNull(Totp.code("JBSWY3DPEHPK3PXP", "SHA1", 6, 30, NOW))
    }

    @Test fun otpauth_uri_is_parsed_into_its_parameters() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        e.set("totp", "otpauth://totp/Shop:me?secret=JBSWY3DPEHPK3PXP&issuer=Shop&algorithm=SHA256&digits=8&period=60")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        val r = storedRecord(store)
        assertEquals(rec("secret" to s("JBSWY3DPEHPK3PXP"), "algorithm" to s("SHA256"), "digits" to i(8), "period" to i(60)), r["totp"])
        Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(r))
    }

    @Test fun existing_secret_is_shown_and_unchanged_save_writes_nothing() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val e = ed(store, items(store)[0])
        assertEquals("JBSWY3DPEHPK3PXP", e.value("totp"))
        assertEquals(SaveResult.UNCHANGED, e.save())
        assertEquals(0, store.commits)
    }

    @Test fun clearing_the_field_removes_the_totp() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val e = ed(store, items(store)[0])
        e.set("totp", "")
        assertEquals(e.error, SaveResult.SAVED, e.save())
        assertNull(storedRecord(store)["totp"])
    }

    @Test fun invalid_secret_is_rejected_with_an_inline_error() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        for (bad in listOf("not base32!", "JBSW", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9")) {
            e.set("totp", bad)
            assertEquals(bad, SaveResult.INVALID, e.save())
            assertNotNull(bad, e.totpError)
            assertEquals(bad, "Check the 2FA secret.", e.error)
        }
        assertEquals(0, store.commits)
        e.set("totp", "JBSWY3DPEHPK3PXP")
        assertNull("editing the field clears its error", e.totpError)
    }

    @Test fun scanned_otpauth_qr_fills_the_field() {
        val store = CountingStore()
        val e = ed(store)
        e.set("label", "Shop"); e.set("origin", "https://shop.example")
        e.scanTotp("otpauth://totp/Shop:me?secret=JBSWY3DPEHPK3PXP&issuer=Shop&digits=8\n")
        assertNull(e.totpError)
        assertEquals(e.error, SaveResult.SAVED, e.save())
        assertEquals(i(8), storedRecord(store).getValue("totp").obj().fields["digits"])
    }

    @Test fun scanned_qr_that_is_not_a_setup_code_keeps_the_field() {
        val e = ed(CountingStore())
        e.set("totp", "JBSWY3DPEHPK3PXP")
        for ((code, message) in listOf(
            "https://shop.example/login" to EnglishTxt().s(R.string.editor_not_totp_qr),
            "" to EnglishTxt().s(R.string.editor_not_totp_qr),
            "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8" to EnglishTxt().s(R.string.editor_migration_qr),
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP" to TotpText.message(TotpException(TotpException.Kind.NOT_OTPAUTH_URI), EnglishTxt()),
        )) {
            e.scanTotp(code)
            assertEquals(code, message, e.totpError)
            assertEquals(code, "JBSWY3DPEHPK3PXP", e.value("totp"))
        }
        e.totpCameraUnavailable()
        assertEquals("The camera is not available. Paste the setup key instead.", e.totpError)
    }

    @Test fun totp_field_is_masked() {
        assertEquals(true, EditorKind.WEB.fields.first { it.key == "totp" }.secret)
    }

    @Test fun unchanged_record_bytes_survive_open_and_save() {
        val store = CountingStore(snapshot(listOf(webLogin)))
        val before = String(CanonicalJson.encode(store.snapshot.records.getValue("w1"), Dialect.UTF8))
        ed(store, items(store)[0]).save()
        assertEquals(before, String(CanonicalJson.encode(store.snapshot.records.getValue("w1"), Dialect.UTF8)))
    }
}
