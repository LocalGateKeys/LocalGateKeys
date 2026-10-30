package app.localgatekeys.android.i18n

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Sweep: no English literal is left in shown Compose text under app/src/main/kotlin. Shown text comes from resources
 * (`stringResource`, `pluralStringResource`, `Txt`). The scan reads whole files, so multi-line calls, named arguments,
 * `if … "A" else "B"` and `"$n items"` templates are caught.
 */
class ComposeTextSweepTest {
    /** Brands and fixed data-format hints that are never translated. */
    private val allowedLiterals = setOf("LocalGateKeys", "YYYY-MM-DD")

    private val literal = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"")
    private val templatePart = Regex("\\$\\{[^}]*}|\\$[A-Za-z_]\\w*")
    private val callStart = Regex("\\b(Text|Icon|Toast\\.makeText|showSnackbar|toast\\.show)\\(")
    private val namedArg = Regex(
        "\\b(label|placeholder|title|supportingText|contentDescription|stateDescription|doneLabel|confirmLabel|onClickLabel|text)\\s*=\\s*(?!\\s|\\{)",
    )
    private val escape = Regex("\\\\.")

    /** Ids and data keys inside an argument are not shown text: `testTag("x")` and `record["x"]`. */
    private val ids = Regex("testTag\\(\"[^\"]*\"\\)|\\[\"[^\"]*\"]")
    private val startsNamed = Regex("^\\s*\\w+\\s*=(?!=)")

    /** True when the literal shows words: letters remain once `$name` and `${expr}` parts are removed. */
    private fun shown(body: String): Boolean {
        if (body in allowedLiterals) return false
        return templatePart.replace(body, "").replace(escape, "").any { it.isLetter() }
    }

    /**
     * The expression that starts at [from]: up to the next top-level comma, the closing bracket, or the end of its line
     * (unless it goes on with `else` or ends in `if`/`else`).
     */
    private fun argument(src: String, from: Int): String {
        var depth = 0
        var i = from
        var inString = false
        while (i < src.length) {
            val ch = src[i]
            if (inString) {
                if (ch == '\\') i++ else if (ch == '"') inString = false
            } else when (ch) {
                '"' -> inString = true
                '(', '[', '{' -> depth++
                ')', ']', '}' -> { if (depth == 0) return src.substring(from, i); depth-- }
                ',' -> if (depth == 0) return src.substring(from, i)
                '\n' -> if (depth == 0) {
                    val sofar = src.substring(from, i).trimEnd()
                    val continues = sofar.isEmpty() || sofar.endsWith("else") || sofar.endsWith("->") ||
                        sofar.endsWith("?:") || src.substring(i).trimStart().startsWith("else")
                    if (!continues) return sofar
                }
            }
            i++
        }
        return src.substring(from)
    }

    private fun lineOf(src: String, index: Int) = src.substring(0, index).count { it == '\n' } + 1

    /** Findings ("line n: literal") for English literals in shown text. [source] is a whole Kotlin file. */
    fun scan(source: String): List<String> {
        val found = ArrayList<String>()
        fun check(start: Int, arg: String) {
            val lineStart = source.lastIndexOf('\n', maxOf(start - 1, 0)) + 1
            val lineEnd = source.indexOf('\n', lineStart).let { if (it < 0) source.length else it }
            val line = source.substring(lineStart, lineEnd)
            if (line.contains("animate") || line.trimStart().startsWith("//")) return
            for (m in literal.findAll(ids.replace(arg, ""))) if (shown(m.groupValues[1])) {
                found += "line ${lineOf(source, start)}: \"${m.groupValues[1]}\""
                return
            }
        }
        for (m in callStart.findAll(source)) {
            val open = m.range.last + 1
            when (m.groupValues[1]) {
                "Text", "toast.show", "showSnackbar" -> {
                    // Text(text = "…") is covered by the named-argument pass below.
                    val first = argument(source, open)
                    if (!startsNamed.containsMatchIn(first)) check(open, first)
                }
                "Toast.makeText" -> check(open, source.substring(open, minOf(source.length, open + 300)).substringBefore(")"))
                "Icon" -> {
                    // Icon(imageVector, "description", …): the second positional argument.
                    val a1 = argument(source, open)
                    val rest = open + a1.length + 1
                    if (rest < source.length) {
                        val second = argument(source, rest)
                        if (!startsNamed.containsMatchIn(second)) check(rest, second)
                    }
                }
            }
        }
        for (m in namedArg.findAll(source)) {
            val start = m.range.last + 1
            check(start, argument(source, start))
        }
        return found.distinct()
    }

    private fun sources(): List<File> {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        return root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    }

    @Test fun no_english_literals_in_shown_text() {
        val found = ArrayList<String>()
        for (file in sources()) {
            val text = file.readText()
            // Files without composables use `text =` and `title =` for data, not for shown text.
            if (!text.contains("@Composable")) continue
            for (f in scan(text)) found += "${file.path}:$f"
        }
        assertTrue("Move these to string resources:\n" + found.joinToString("\n"), found.isEmpty())
    }

    @Test fun the_sweep_finds_the_sources() {
        assertTrue(sources().size > 100)
    }

    @Test fun the_scan_catches_every_pattern_it_exists_for() {
        val caught = mapOf(
            "plain" to "Text(\"Hello\")",
            "named text" to "Text(text = \"Foo\")",
            "next line" to "Text(\n    \"Foo bar\",\n    color = c)",
            "if else" to "Text(if (a) \"Yes\" else \"No\")",
            "if else, lines" to "Text(\n    if (a) \"Yes\"\n    else \"No\")",
            "lowercase" to "Text(\"sync now\")",
            "digit first" to "Text(\"2FA codes\")",
            "template" to "Text(\"\$n items\")",
            "label" to "OutlinedTextField(label = \"Name\")",
            "placeholder" to "TextField(placeholder = \"Search\")",
            "title" to "AlertDialog(title = \"Delete?\")",
            "supportingText" to "TextField(supportingText = \"Required\")",
            "contentDescription" to "Modifier.semantics { contentDescription = \"Back\" }",
            "contentDescription if" to "contentDescription = if (on) \"Hide\" else \"Show\"",
            "toast" to "Toast.makeText(context, \"Saved\", Toast.LENGTH_SHORT).show()",
            "toast seam" to "seams.toast.show(\"Code copied\")",
            "snackbar" to "host.showSnackbar(\"Undo available\")",
            "icon" to "Icon(Icons.Filled.Check, \"Selected\")",
        )
        for ((name, snippet) in caught) assertTrue("not caught: $name", scan(snippet).isNotEmpty())
    }

    @Test fun the_scan_lets_resources_brands_and_ids_through() {
        val clean = listOf(
            "Text(stringResource(R.string.common_ok))",
            "Text(txt.s(R.string.common_ok), color = c.text)",
            "Text(name, color = c.text)",
            "Text(\"\$seconds\")",
            "Text(\"LocalGateKeys\", fontSize = 28.sp)",
            "Text(\"YYYY-MM-DD\")",
            "Modifier.testTag(\"settings-list\")",
            "animateFloatAsState(target, spec, label = \"ring\")",
            "Icon(Icons.Filled.Check, null)",
            "Icon(Icons.Filled.Check, stringResource(R.string.common_selected))",
        )
        for (snippet in clean) assertEquals("flagged: $snippet", emptyList<String>(), scan(snippet))
    }
}
