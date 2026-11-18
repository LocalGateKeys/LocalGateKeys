package app.localgatekeys.core.notes

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The shared Markdown vectors (tests/vectors/markdown/cases.json, copied to test resources) plus timing guards. */
class NoteMarkdownTest {
    private val cases: List<JsonValue> = CanonicalJson.parse(
        javaClass.getResourceAsStream("/markdown_cases.json")!!.use { it.readBytes() },
    ).arr()

    private fun str(v: String) = JsonValue.Str(v)
    private fun obj(vararg f: Pair<String, JsonValue>) = JsonValue.Obj(mapOf(*f))
    private fun inlines(c: List<MdInline>) = JsonValue.Arr(c.map(::inline))

    private fun inline(n: MdInline): JsonValue = when (n) {
        is MdInline.Text -> obj("t" to str("text"), "v" to str(n.v))
        is MdInline.Bold -> obj("t" to str("b"), "c" to inlines(n.content))
        is MdInline.Italic -> obj("t" to str("i"), "c" to inlines(n.content))
        is MdInline.Code -> obj("t" to str("code"), "v" to str(n.v))
        is MdInline.Link -> obj("t" to str("link"), "text" to str(n.text), "url" to str(n.url))
    }

    private fun block(n: MdNode): JsonValue = when (n) {
        is MdNode.Heading -> obj("t" to str("h"), "level" to JsonValue.Int(n.level.toLong()), "c" to inlines(n.content))
        is MdNode.Paragraph -> obj("t" to str("p"), "c" to inlines(n.content))
        is MdNode.Bullets -> obj("t" to str("ul"), "items" to JsonValue.Arr(n.items.map(::inlines)))
        is MdNode.Numbered -> obj("t" to str("ol"), "items" to JsonValue.Arr(n.items.map(::inlines)))
        is MdNode.Todos -> obj(
            "t" to str("todo"),
            "items" to JsonValue.Arr(n.items.map { obj("done" to JsonValue.Bool(it.done), "c" to inlines(it.content)) }),
        )
        is MdNode.CodeBlock -> obj("t" to str("code"), "text" to str(n.text))
        MdNode.Rule -> obj("t" to str("hr"))
    }

    @Test fun there_are_vectors() {
        assertTrue(cases.size >= 30, "only ${cases.size} cases loaded")
    }

    @Test fun every_vector_matches_node_for_node() {
        for (case in cases) {
            val o = case.obj().fields
            val name = o.getValue("name").str()
            val got = JsonValue.Arr(NoteMarkdown.parse(o.getValue("input").str()).map(::block))
            assertEquals(o.getValue("nodes"), got, "vector $name")
        }
    }

    @Test fun never_throws_on_odd_input() {
        for (s in listOf("", "*", "**", "`", "[", "[]()", "[a](", "```", "- ", "1.", "\u0000", "\r", "*a*b**c`d[e](f)")) {
            NoteMarkdown.parse(s)
        }
    }

    /** An unclosed `*` per word must not rescan to the end of the run each time (a quadratic port takes seconds). */
    @Test fun many_unclosed_openers_parse_in_linear_time() {
        val text = "*a ".repeat(6666)
        NoteMarkdown.parse(text) // warm up the JIT so the timing below measures the algorithm
        val start = System.nanoTime()
        NoteMarkdown.parse(text)
        val ms = (System.nanoTime() - start) / 1_000_000
        assertTrue(ms < 100, "took $ms ms")
    }
}
