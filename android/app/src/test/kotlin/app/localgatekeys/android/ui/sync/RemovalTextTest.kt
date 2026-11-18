package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

class RemovalTextTest {
    private val t = EnglishTxt()
    private val name: (String) -> String = { it.uppercase() }
    private val members = listOf("a", "b", "c", "d")

    @Test fun keepersExcludeRemovedAndUnconfirmedAndEndWithThisPhone() {
        assertEquals(listOf("B", "This phone"), RemovalText.keepers(members, setOf("a", "c"), setOf("d"), "This phone", name))
    }

    @Test fun keepersOfEveryoneRemovedIsOnlyThisPhone() {
        assertEquals(listOf("This phone"), RemovalText.keepers(members, members.toSet(), emptySet(), "This phone", name))
    }

    @Test fun losingAccessSkipsUnconfirmedMembersThatAreBeingRemoved() {
        assertEquals(listOf("D"), RemovalText.losingAccess(members, setOf("a", "c"), setOf("c", "d"), name))
    }

    @Test fun keepTextWithoutUnconfirmedHasNoWarning() {
        val text = RemovalText.keepText(members, setOf("a"), emptySet(), "This phone", t, name)
        assertEquals("The new sync key goes only to: B, C, D, This phone.", text)
    }

    @Test fun keepTextWarnsAboutUnconfirmedMembersThatStay() {
        val text = RemovalText.keepText(members, setOf("a"), setOf("d"), "This phone", t, name)
        assertTrue(text.startsWith("The new sync key goes only to: B, C, This phone."))
        assertTrue(text.contains("Not confirmed, so they lose access: D."))
        val removed = RemovalText.keepText(members, setOf("a", "d"), setOf("d"), "This phone", t, name)
        assertFalse(removed.contains("Not confirmed"))
    }

    @Test fun displayNameSanitizesTheKeyringNameAndFallsBackToTheShortId() {
        val words = SyncWording(t)
        val membership = SyncCoordinator.Membership(names = mapOf("a" to "Ali\u0007ce\n phone", "b" to null))
        assertEquals("Alice phone · Device a", RemovalText.displayName("a", membership, words))
        assertEquals("Device b", RemovalText.displayName("b", membership, words))
        assertEquals("Device c", RemovalText.displayName("c", membership, words))
    }
}
