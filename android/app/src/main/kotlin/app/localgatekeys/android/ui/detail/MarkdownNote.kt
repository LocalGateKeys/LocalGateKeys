package app.localgatekeys.android.ui.detail

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.localgatekeys.android.R
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.core.notes.MdInline
import app.localgatekeys.core.notes.MdNode
import app.localgatekeys.core.notes.NoteMarkdown

/** Which detail fields are note text: a login's `notes`, and the `body` of a secure note. Nothing else is formatted. */
internal fun formatsAsMarkdown(kind: String, fieldId: String): Boolean =
    fieldId == "notes" || (kind == "note" && fieldId == "body")

/**
 * A note with the Markdown subset applied (display only): headings, bold, italic, code, lists and rules. Links are
 * never clickable (they read "text (url)") and checklist boxes are not tappable. Selection is off like every value.
 */
@Composable
internal fun MarkdownNote(text: String, modifier: Modifier = Modifier) {
    val c = LgkTheme.colors
    val blocks = remember(text) { NoteMarkdown.parse(text) }
    val body = MaterialTheme.typography.bodyLarge
    val codeBg = c.separator
    Column(modifier, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        for (block in blocks) {
            when (block) {
                is MdNode.Heading -> Text(
                    markdownInline(block.content, codeBg, c.accentText),
                    color = c.text,
                    style = body.copy(
                        fontWeight = FontWeight.Bold,
                        fontSize = when (block.level) { 1 -> 24.sp; 2 -> 20.sp; else -> 18.sp },
                    ),
                )
                is MdNode.Paragraph -> Text(markdownInline(block.content, codeBg, c.accentText), color = c.text, style = body)
                is MdNode.Bullets -> block.items.forEach { ListLine("\u2022", it, codeBg, body) }
                is MdNode.Numbered -> block.items.forEachIndexed { i, it -> ListLine("${i + 1}.", it, codeBg, body) }
                is MdNode.Todos -> block.items.forEach { ListLine(if (it.done) CHECKED else UNCHECKED, it.content, codeBg, body) }
                is MdNode.CodeBlock -> Text(
                    block.text, color = c.text, fontFamily = FontFamily.Monospace, style = body,
                    modifier = Modifier.fillMaxWidth().background(codeBg, RoundedCornerShape(8.dp)).padding(8.dp),
                )
                MdNode.Rule -> Box(Modifier.fillMaxWidth().padding(vertical = 4.dp).height(1.dp).background(c.separator))
            }
        }
    }
}

private const val CHECKED = "\u2611"
private const val UNCHECKED = "\u2610"

@Composable
private fun ListLine(marker: String, content: List<MdInline>, codeBg: Color, style: TextStyle) {
    val c = LgkTheme.colors
    val spoken = when (marker) {
        CHECKED -> stringResource(R.string.notes_todo_done)
        UNCHECKED -> stringResource(R.string.notes_todo_not_done)
        else -> null
    }
    Row {
        Text(
            marker, color = c.secondaryText, style = style,
            modifier = Modifier.padding(end = 8.dp).then(if (spoken != null) Modifier.semantics { contentDescription = spoken } else Modifier),
        )
        Text(markdownInline(content, codeBg, c.accentText), color = c.text, style = style)
    }
}

/** Inline nodes as one styled string. A link is plain text "text (url)" in the accent colour: no click target. */
internal fun markdownInline(nodes: List<MdInline>, codeBackground: Color, linkColor: Color): AnnotatedString =
    buildAnnotatedString { appendInline(nodes, codeBackground, linkColor) }

private fun AnnotatedString.Builder.appendInline(nodes: List<MdInline>, codeBackground: Color, linkColor: Color) {
    for (n in nodes) {
        when (n) {
            is MdInline.Text -> append(n.v)
            is MdInline.Bold -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { appendInline(n.content, codeBackground, linkColor) }
            is MdInline.Italic -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { appendInline(n.content, codeBackground, linkColor) }
            is MdInline.Code -> withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = codeBackground)) { append(n.v) }
            is MdInline.Link -> withStyle(SpanStyle(color = linkColor, textDecoration = TextDecoration.Underline)) { append("${n.text} (${n.url})") }
        }
    }
}
