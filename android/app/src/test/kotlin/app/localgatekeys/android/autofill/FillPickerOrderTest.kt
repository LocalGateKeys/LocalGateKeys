package app.localgatekeys.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class FillPickerOrderTest {
    private fun row(id: String, title: String, user: String = "") = FillPickerOrder.Row(id, title, user)

    private val rows = listOf(row("1", "Shop", "sam"), row("2", "bank", "sam.r"), row("3", "Airline"), row("4", "Mail", "sam@x"))

    @Test
    fun matchesComeFirstInMatcherOrderAndOthersByTitle() {
        val s = FillPickerOrder.split(rows, listOf("4", "1"))
        assertEquals(listOf("4", "1"), s.matches.map { it.id })
        assertEquals(listOf("3", "2"), s.others.map { it.id })
    }

    @Test
    fun noLoginIsAddedOrDropped() {
        val s = FillPickerOrder.split(rows, listOf("1", "missing", "1"))
        assertEquals(listOf("1"), s.matches.map { it.id })
        assertEquals(rows.map { it.id }.toSet(), (s.matches + s.others).map { it.id }.toSet())
        assertEquals(rows.size, s.matches.size + s.others.size)
    }

    @Test
    fun noMatchesListsEverythingByTitle() {
        val s = FillPickerOrder.split(rows, emptyList())
        assertEquals(emptyList<String>(), s.matches.map { it.id })
        assertEquals(listOf("3", "2", "4", "1"), s.others.map { it.id })
    }

    @Test
    fun filterMatchesTitleOrUsernameAnyCase() {
        assertEquals(listOf("2"), FillPickerOrder.filter(rows, " BANK ").map { it.id })
        assertEquals(listOf("4"), FillPickerOrder.filter(rows, "@x").map { it.id })
        assertEquals(rows, FillPickerOrder.filter(rows, "  "))
    }

    @Test
    fun initialFallsBackToUsername() {
        assertEquals("B", FillPickerOrder.initial(row("x", "bank")))
        assertEquals("S", FillPickerOrder.initial(row("x", "", "sam")))
        assertEquals("?", FillPickerOrder.initial(row("x", "")))
    }
}
