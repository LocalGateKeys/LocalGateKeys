package app.localgatekeys.core.notes

/*
 * The Markdown subset for notes (display only). The grammar and the node shapes are pinned by
 * tests/vectors/markdown/cases.json and described in tests/vectors/markdown/README.md; this is a port of
 * webui/src/lib/markdown.js and must return the same nodes for every case. Nothing here produces HTML or links.
 */

/** A block node. */
sealed interface MdNode {
    data class Heading(val level: Int, val content: List<MdInline>) : MdNode
    data class Paragraph(val content: List<MdInline>) : MdNode
    data class Bullets(val items: List<List<MdInline>>) : MdNode

    /** Numbers are not kept: renderers number the items 1, 2, 3... */
    data class Numbered(val items: List<List<MdInline>>) : MdNode
    data class Todos(val items: List<TodoItem>) : MdNode
    data class CodeBlock(val text: String) : MdNode
    data object Rule : MdNode
}

data class TodoItem(val done: Boolean, val content: List<MdInline>)

/** An inline node. Empty [Text] nodes are never emitted and adjacent ones are merged. */
sealed interface MdInline {
    data class Text(val v: String) : MdInline
    data class Bold(val content: List<MdInline>) : MdInline
    data class Italic(val content: List<MdInline>) : MdInline
    data class Code(val v: String) : MdInline

    /** Shown as "text (url)", never clickable; kept even for `javascript:` URLs. */
    data class Link(val text: String, val url: String) : MdInline
}

object NoteMarkdown {
    /** Longer text is not parsed: it comes back as one paragraph (UTF-16 units). */
    const val MAX_CHARS = 20000

    private enum class Kind { TODO, UL, OL }

    private class Item(val kind: Kind, val done: Boolean, val text: String)

    /** The list being collected; it becomes a node when the list ends. */
    private class PendingList(val kind: Kind) {
        val plain = mutableListOf<List<MdInline>>()
        val todos = mutableListOf<TodoItem>()

        fun node(): MdNode = when (kind) {
            Kind.TODO -> MdNode.Todos(todos)
            Kind.UL -> MdNode.Bullets(plain)
            Kind.OL -> MdNode.Numbered(plain)
        }
    }

    /** Text -> block nodes. Never throws; any input gives a node list. */
    fun parse(text: String): List<MdNode> {
        val src = text.replace("\r\n", "\n").replace('\r', '\n')
        if (src.length > MAX_CHARS) return listOf(MdNode.Paragraph(listOf(MdInline.Text(src))))
        val lines = src.split('\n')
        val out = mutableListOf<MdNode>()
        val para = mutableListOf<String>()
        var list: PendingList? = null
        fun flushPara() {
            if (para.isNotEmpty()) out.add(MdNode.Paragraph(parseInline(para.joinToString("\n"))))
            para.clear()
        }
        fun flushList() {
            list?.let { out.add(it.node()) }
            list = null
        }
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            if (line.startsWith("```")) {
                flushPara()
                flushList()
                val body = mutableListOf<String>()
                i++
                while (i < lines.size && !lines[i].startsWith("```")) body.add(lines[i++])
                out.add(MdNode.CodeBlock(body.joinToString("\n")))
                i++ // the closing fence line (or past the end when unclosed)
                continue
            }
            if (isBlank(line)) { flushPara(); flushList(); i++; continue }
            if (line == "---") { flushPara(); flushList(); out.add(MdNode.Rule); i++; continue }
            val level = headingLevel(line)
            if (level > 0 && trim(line.substring(level + 1)).isNotEmpty()) {
                flushPara()
                flushList()
                out.add(MdNode.Heading(level, parseInline(trim(line.substring(level + 1)))))
                i++
                continue
            }
            val item = listItem(line)
            if (item != null) {
                flushPara()
                val content = parseInline(trim(item.text))
                if (list?.kind != item.kind) {
                    flushList()
                    list = PendingList(item.kind)
                }
                if (item.kind == Kind.TODO) list!!.todos.add(TodoItem(item.done, content)) else list!!.plain.add(content)
                i++
                continue
            }
            flushList()
            para.add(line)
            i++
        }
        flushPara()
        flushList()
        return out
    }

    private fun isBlank(line: String) = line.all { it == ' ' || it == '\t' }
    private fun trim(s: String) = s.trim { it == ' ' || it == '\t' }
    private fun isSpace(c: Char) = c == ' ' || c == '\t' || c == '\n'

    /**
     * 1-3 when the line starts with that many `#` and then a space, else 0. A line holding U+2028 or U+2029 is never
     * a heading: the reference parser's regex `.` does not match them (tests/vectors/markdown/README.md).
     */
    private fun headingLevel(line: String): Int {
        if (line.contains('\u2028') || line.contains('\u2029')) return 0
        var n = 0
        while (n < line.length && line[n] == '#') n++
        return if (n in 1..3 && n < line.length && line[n] == ' ') n else 0
    }

    private fun listItem(line: String): Item? {
        if (line.startsWith("- [ ] ")) return Item(Kind.TODO, false, line.substring(6))
        if (line.startsWith("- [x] ") || line.startsWith("- [X] ")) return Item(Kind.TODO, true, line.substring(6))
        if (line.startsWith("- ") || line.startsWith("* ")) return Item(Kind.UL, false, line.substring(2))
        var n = 0
        while (n < line.length && line[n] in '0'..'9') n++
        return if (n > 0 && line.startsWith(". ", n)) Item(Kind.OL, false, line.substring(n + 2)) else null
    }

    // One pass over an inline run: where code spans and links start and end, so no scan ever repeats.
    // skip[i] = index just past the code span or link that starts at i (0 = none); linkK[i] = the link's ']'.
    private class Spans(val skip: IntArray, val linkK: IntArray)

    private fun analyze(s: String): Spans {
        val n = s.length
        val skip = IntArray(n + 1)
        val linkK = IntArray(n + 1)
        val nextTick = IntArray(n + 2) { -1 }
        val nextClose = IntArray(n + 2) { -1 }
        val nextSpace = IntArray(n + 2) { -1 }
        val nextNewline = IntArray(n + 2) { -1 }
        val bal = IntArray(n + 1)
        for (i in n - 1 downTo 0) {
            val c = s[i]
            nextTick[i] = if (c == '`') i else nextTick[i + 1]
            nextClose[i] = if (c == ']') i else nextClose[i + 1]
            nextSpace[i] = if (isSpace(c)) i else nextSpace[i + 1]
            nextNewline[i] = if (c == '\n') i else nextNewline[i + 1]
        }
        for (i in 0 until n) bal[i + 1] = bal[i] + (if (s[i] == '(') 1 else if (s[i] == ')') -1 else 0)
        // unbalanced[p] = index of the first ')' at or after p that no '(' at or after p balances, or -1.
        val unbalanced = IntArray(n + 1) { -1 }
        val firstAt = HashMap<Int, Int>()
        for (p in n downTo 0) {
            val x = firstAt[bal[p] - 1]
            if (x != null) unbalanced[p] = x - 1
            firstAt[bal[p]] = p
        }
        for (i in 0 until n) {
            if (s[i] == '`') {
                val j = nextTick[i + 1]
                if (j > i + 1) skip[i] = j + 1
            } else if (s[i] == '[') {
                val k = nextClose[i + 1]
                if (k < 0 || k == i + 1 || k + 1 >= n || s[k + 1] != '(') continue
                val nl = nextNewline[i + 1]
                if (nl in 0 until k) continue
                val p = k + 2
                val j = unbalanced[p]
                val w = nextSpace[p]
                if (j < 0 || j == p || (w in 0 until j)) continue
                skip[i] = j + 1
                linkK[i] = k
            }
        }
        return Spans(skip, linkK)
    }

    // closer[j] = index of the closing marker at or after j, skipping code spans and links; -1 if none. A closer
    // must follow a non-space character. While looking for "*", a "**" pair is skipped as a unit. The scan's steps
    // do not depend on where it started, so the answer from every position is computed once.
    private fun closers(s: String, skip: IntArray, marker: String): IntArray {
        val n = s.length
        val res = IntArray(n + 3) { -1 }
        for (j in n - 1 downTo 0) {
            if (skip[j] > 0) { res[j] = res[skip[j]]; continue }
            if (marker == "*" && s.startsWith("**", j)) { res[j] = res[j + 2]; continue }
            res[j] = if (j > 0 && s.startsWith(marker, j) && !isSpace(s[j - 1])) j else res[j + 1]
        }
        return res
    }

    private fun parseInline(s: String): List<MdInline> {
        val out = mutableListOf<MdInline>()
        val buf = StringBuilder()
        fun flush() {
            if (buf.isNotEmpty()) out.add(MdInline.Text(buf.toString()))
            buf.setLength(0)
        }
        val spans = analyze(s)
        val skip = spans.skip
        val closing = HashMap<String, IntArray>()
        fun closeAt(from: Int, marker: String): Int {
            val table = closing.getOrPut(marker) { closers(s, skip, marker) }
            // The opener itself is never the closer: continue from its own step.
            val next = if (skip[from] > 0) skip[from] else if (marker == "*" && s.startsWith("**", from)) from + 2 else from + 1
            return table[next]
        }
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c == '`') {
                if (skip[i] > 0) { flush(); out.add(MdInline.Code(s.substring(i + 1, skip[i] - 1))); i = skip[i]; continue }
            } else if (c == '[') {
                if (skip[i] > 0) {
                    flush()
                    out.add(MdInline.Link(s.substring(i + 1, spans.linkK[i]), s.substring(spans.linkK[i] + 2, skip[i] - 1)))
                    i = skip[i]
                    continue
                }
            } else if (c == '*') {
                val marker = if (s.startsWith("**", i)) "**" else "*"
                val open = i + marker.length
                if (open < s.length && !isSpace(s[open])) {
                    val close = closeAt(open, marker)
                    if (close > 0) {
                        flush()
                        val inner = parseInline(s.substring(open, close))
                        out.add(if (marker == "**") MdInline.Bold(inner) else MdInline.Italic(inner))
                        i = close + marker.length
                        continue
                    }
                }
            }
            buf.append(c)
            i++
        }
        flush()
        return out
    }
}
