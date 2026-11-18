package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.Vectors
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class TravelModeTest {
    private val col1 = "11111111-1111-4111-8111-111111111111"
    private val col2 = "22222222-2222-4222-8222-222222222222"

    private val items = listOf(
        TravelMode.Item("bank", "web", listOf("  bank "), emptyList()),
        TravelMode.Item("oldrow", "web", emptyList(), listOf(col1)),
        TravelMode.Item("card", "card", emptyList(), listOf(col2, col1)),
        TravelMode.Item("note", "note", listOf("Home"), listOf(col2)),
    )

    @Test
    fun offHidesNothing() {
        assertTrue(TravelMode.hiddenIds(items, TravelMode.Setting(on = false, collections = listOf(col1), tags = listOf("Bank"))).isEmpty())
    }

    @Test
    fun hidesByTagFoldAndCollectionForTypedItemsOnly() {
        val set = TravelMode.Setting(on = true, collections = listOf(col1, "33333333-3333-4333-8333-333333333333"), tags = listOf("BANK"))
        assertEquals(setOf("bank", "card"), TravelMode.hiddenIds(items, set))
    }

    @Test
    fun settingRoundTripAndCleaning() {
        val s = TravelMode.Setting(true, listOf(col1.uppercase(), "nope", col1), listOf("Bank", " bank ", "", "Trip"), 9)
        val back = TravelMode.Setting.of(s.json())
        assertEquals(listOf(col1), back.collections)
        assertEquals(listOf("Bank", "Trip"), back.tags)
        assertEquals(9L, back.since)
        assertEquals(TravelMode.Setting.OFF, TravelMode.Setting.of(JsonValue.Str("x")))
    }

    @Test
    fun visibleVectors() {
        val root = Vectors.json(Vectors.optional("travel/visible.json"))
        val list = (root as? JsonValue.Arr)?.items ?: ((root as JsonValue.Obj).fields["cases"] as JsonValue.Arr).items
        fun strs(v: JsonValue?) = (v as? JsonValue.Arr)?.items?.map { (it as JsonValue.Str).v } ?: emptyList()
        for (c in list.map { (it as JsonValue.Obj).fields }) {
            val its = (c.getValue("items") as JsonValue.Arr).items.map {
                val f = (it as JsonValue.Obj).fields
                TravelMode.Item((f.getValue("id") as JsonValue.Str).v, (f.getValue("kind") as JsonValue.Str).v, strs(f["tags"]), strs(f["collections"]))
            }
            val sf = (c.getValue("setting") as JsonValue.Obj).fields
            val setting = TravelMode.Setting(sf["on"] == JsonValue.Bool(true), strs(sf["collections"]), strs(sf["tags"]))
            assertEq("${c["name"]}", strs(c["expected_hidden"]).toSet(), TravelMode.hiddenIds(its, setting))
        }
    }

    @Test
    fun visibleCollectionsLeavesOutHiddenOnesOnlyWhileOn() {
        val a = "a0000000-0000-4000-8000-000000000001"
        val b = "b0000000-0000-4000-8000-000000000002"
        val on = TravelMode.Setting(true, listOf(a), emptyList(), 1)
        assertEq("on", listOf(b), TravelMode.visibleCollections(listOf(a.uppercase(), b), on) { it })
        assertEq("off", listOf(a, b), TravelMode.visibleCollections(listOf(a, b), on.copy(on = false)) { it })
    }
}
