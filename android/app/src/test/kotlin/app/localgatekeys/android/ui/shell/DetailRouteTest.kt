package app.localgatekeys.android.ui.shell

import app.localgatekeys.android.vault.card
import app.localgatekeys.android.vault.itemsOf
import app.localgatekeys.android.vault.webLogin
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The open detail closes once a loaded list no longer has its item, including when the list becomes empty. */
class DetailRouteTest {
    private val both = itemsOf(webLogin, card)

    @Test fun an_item_still_listed_stays_open() {
        assertEquals("w1", DetailRoute.keep("w1", both, loaded = true))
    }

    @Test fun a_removed_item_closes() {
        assertNull(DetailRoute.keep("w1", itemsOf(card), loaded = true))
    }

    @Test fun the_last_item_removed_closes_too() {
        assertNull(DetailRoute.keep("w1", emptyList(), loaded = true))
    }

    @Test fun before_the_first_load_the_id_is_kept() {
        assertEquals("w1", DetailRoute.keep("w1", emptyList(), loaded = false))
    }

    @Test fun nothing_open_stays_nothing() {
        assertNull(DetailRoute.keep(null, both, loaded = true))
    }
}
