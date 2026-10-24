package app.localgatekeys.android.vault

import app.localgatekeys.android.editor.EditorKind
import app.localgatekeys.android.pro.ItemLimit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuickActionsTest {
    private val byId = itemsOf(webLogin, deskLogin, note, card).associateBy { it.id }

    @Test fun a_login_with_everything_offers_all_four_actions_in_order() {
        val actions = QuickActions.forItem(byId["w1"]!!)
        assertEquals(
            listOf("Copy username", "Copy password", "Copy 2FA code", "Open website"),
            actions.map { it.label },
        )
        assertEquals(
            listOf(
                QuickAction.Kind.COPY_USERNAME, QuickAction.Kind.COPY_PASSWORD,
                QuickAction.Kind.COPY_CODE, QuickAction.Kind.OPEN_WEBSITE,
            ),
            actions.map { it.kind },
        )
        assertEquals(listOf("Username copied", "Password copied", "Code copied", null), actions.map { it.confirmation })
    }

    @Test fun actions_only_appear_when_there_is_something_to_copy_or_open() {
        assertEquals(listOf("Copy username", "Copy password"), QuickActions.forItem(byId["d1"]!!).map { it.label })
        assertTrue(QuickActions.forItem(byId["n1"]!!).isEmpty())
        assertTrue(QuickActions.forItem(byId["c1"]!!).isEmpty())
        val wifi = item("wifi", "title" to s("Home"), "payload" to rec("password" to s("hunter22")))
        assertEquals(listOf("Copy password"), QuickActions.forItem(wifi).map { it.label })
        val bookmark = item("bookmark", "payload" to rec("url" to s("https://example.org")))
        assertEquals(listOf("Open website"), QuickActions.forItem(bookmark).map { it.label })
    }

    @Test fun codes_row_shows_only_with_the_setting_on_and_a_two_factor_item() {
        val items = byId.values.toList()
        assertEquals(listOf("w1"), CodesRow.items(items, showCodesRow = true).map { it.id })
        assertTrue(CodesRow.items(items, showCodesRow = false).isEmpty())
        assertTrue(CodesRow.items(items.filter { !it.hasTotp }, showCodesRow = true).isEmpty())
    }

    @Test fun the_plus_menu_has_the_three_sections_with_the_iphone_labels() {
        val labels = EditorKind.menuSections.map { s -> s.map { it.label } }
        assertEquals(
            listOf(
                listOf("Website login", "Note", "Payment card", "Identity"),
                listOf("Bank account", "Purchase", "Subscription", "Warranty"),
                listOf("Wi-Fi network", "License", "API key", "SSH key", "Bookmark"),
            ),
            labels,
        )
    }

    @Test fun creating_needs_a_free_slot_or_pro() {
        val full = snapshot(listOf(webLogin, deskLogin, note, card))
        val three = snapshot(listOf(webLogin, deskLogin, note))
        assertEquals(NewItemGate.Decision.OPEN_EDITOR, NewItemGate.decide(three, isPro = false))
        assertEquals(NewItemGate.Decision.UPGRADE, NewItemGate.decide(full, isPro = false))
        assertEquals(NewItemGate.Decision.OPEN_EDITOR, NewItemGate.decide(full, isPro = true))
        assertFalse(ItemLimit.allows(ItemLimit.Action.CREATE, full, false))
        // no snapshot yet (the first load failed): the editor is not blocked by a limit we cannot count
        assertEquals(NewItemGate.Decision.OPEN_EDITOR, NewItemGate.decide(null, isPro = false))
    }
}
