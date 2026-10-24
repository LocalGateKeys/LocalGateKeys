package app.localgatekeys.android.ui.shell

import app.localgatekeys.android.detail.passkeyItem
import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.ui.detail.DetailAction
import app.localgatekeys.android.vault.card
import app.localgatekeys.android.vault.deskLogin
import app.localgatekeys.android.vault.itemsOf
import app.localgatekeys.android.vault.webLogin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The editor route RootScaffold keeps, and which toolbar action the detail offers (iOS ItemDetailView toolbar). */
class EditorRouteTest {
    @Test fun routes_round_trip_through_their_keys() {
        for (r in listOf(EditorRoute.New(EditorKind.WIFI), EditorRoute.Edit("w1"), EditorRoute.Passkey("p1"))) {
            assertEquals(r, EditorRoute.parse(r.key))
        }
        assertNull(EditorRoute.parse("new:passkey"))
        assertNull(EditorRoute.parse("edit:"))
        assertNull(EditorRoute.parse("other:x"))
    }

    @Test fun items_route_to_the_editor_the_rename_screen_or_nothing() {
        val items = itemsOf(webLogin, card, deskLogin, passkeyItem()).associateBy { it.kind }
        assertEquals(EditorRoute.Edit("w1"), EditorRoute.forItem(items.getValue("web")))
        assertEquals(EditorRoute.Edit("c1"), EditorRoute.forItem(items.getValue("card")))
        assertEquals(EditorRoute.Passkey(items.getValue("passkey").id), EditorRoute.forItem(items.getValue("passkey")))
        assertNull(EditorRoute.forItem(items.getValue("desktop")))
    }

    @Test fun the_detail_toolbar_offers_edit_or_delete_by_kind() {
        assertEquals(DetailAction.EDIT, DetailAction.of("web"))
        assertEquals(DetailAction.EDIT, DetailAction.of("ssh_key"))
        assertEquals(DetailAction.EDIT, DetailAction.of("passkey"))
        assertEquals(DetailAction.DELETE, DetailAction.of("desktop"))
        assertEquals(DetailAction.DELETE, DetailAction.of("document"))
    }
}
