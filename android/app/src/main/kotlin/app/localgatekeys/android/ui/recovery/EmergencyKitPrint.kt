package app.localgatekeys.android.ui.recovery

import android.content.Context
import android.content.ContextWrapper
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.text.StaticLayout
import android.text.TextPaint
import app.localgatekeys.android.BuildConfig
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.recovery.EmergencyKit
import java.io.FileOutputStream
import java.text.DateFormat
import java.util.Date

/**
 * Prints the emergency kit through the system print UI (which also offers "Save as PDF"); no file of ours is written.
 * The recovery phrase [words] are only held by the adapter while the job runs and are dropped in `onFinish`.
 */
object EmergencyKitPrint {
    /** [words]: the phrase the calling screen holds in memory, or null for blank boxes. Needs an Activity context. */
    fun print(context: Context, txt: Txt, words: List<String>?) {
        val activity = generateSequence(context) { (it as? ContextWrapper)?.baseContext }.firstOrNull { it is android.app.Activity } ?: return
        val manager = activity.getSystemService(Context.PRINT_SERVICE) as? PrintManager ?: return
        val facts = EmergencyKit.Facts(
            date = DateFormat.getDateInstance(DateFormat.LONG).format(Date()),
            appVersion = BuildConfig.VERSION_NAME,
            device = Build.MODEL,
        )
        val blocks = EmergencyKit.build(txt, facts, words)
        val title = blocks.filterIsInstance<EmergencyKit.Block.Title>().first().text
        manager.print(title, KitAdapter(activity, blocks, title), null)
    }
}

/** One drawable piece of a page: [height] in points, [draw] paints it with its top at the given y. */
private class Piece(val height: Float, val keepWithNext: Boolean = false, val draw: (Canvas, Float) -> Unit)

private class KitAdapter(private val context: Context, blocks: List<EmergencyKit.Block>, private val jobName: String) : PrintDocumentAdapter() {
    // Cleared in onFinish; the phrase lives in these blocks and in the pieces drawn from them.
    private var blocks: List<EmergencyKit.Block>? = blocks
    private var pieces: List<List<Piece>> = emptyList()
    private var pageWidth = A4_WIDTH
    private var pageHeight = A4_HEIGHT

    override fun onLayout(
        oldAttributes: PrintAttributes?, newAttributes: PrintAttributes, cancellationSignal: CancellationSignal?,
        callback: LayoutResultCallback, extras: Bundle?,
    ) {
        if (cancellationSignal?.isCanceled == true) { callback.onLayoutCancelled(); return }
        val size = newAttributes.mediaSize
        pageWidth = size?.let { it.widthMils * 72f / 1000f } ?: A4_WIDTH
        pageHeight = size?.let { it.heightMils * 72f / 1000f } ?: A4_HEIGHT
        val current = blocks
        if (current == null) { callback.onLayoutFailed(null); return }
        pieces = paginate(current.flatMap { piecesFor(it, pageWidth - 2 * MARGIN) }, pageHeight - 2 * MARGIN)
        val info = PrintDocumentInfo.Builder(jobName)
            .setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT)
            .setPageCount(pieces.size)
            .build()
        callback.onLayoutFinished(info, true)
    }

    override fun onWrite(
        pages: Array<out PageRange>, destination: ParcelFileDescriptor, cancellationSignal: CancellationSignal?,
        callback: WriteResultCallback,
    ) {
        val doc = PdfDocument()
        try {
            for ((index, page) in pieces.withIndex()) {
                if (cancellationSignal?.isCanceled == true) { callback.onWriteCancelled(); return }
                if (!wanted(pages, index)) continue
                val p = doc.startPage(PdfDocument.PageInfo.Builder(pageWidth.toInt(), pageHeight.toInt(), index).create())
                var y = MARGIN
                for (piece in page) { piece.draw(p.canvas, y); y += piece.height }
                doc.finishPage(p)
            }
            FileOutputStream(destination.fileDescriptor).use { doc.writeTo(it) }
            callback.onWriteFinished(Array(pages.size) { pages[it] })
        } catch (e: Exception) {
            callback.onWriteFailed(null) // no detail: the message could carry nothing secret, but there is nothing to add
        } finally {
            doc.close()
        }
    }

    /** The print job is over (done or cancelled): drop the phrase. */
    override fun onFinish() {
        blocks = null
        pieces = emptyList()
    }

    private fun wanted(ranges: Array<out PageRange>, index: Int) =
        ranges.any { it == PageRange.ALL_PAGES || (index >= it.start && index <= it.end) }

    /** Fills pages top to bottom; a heading stays with the piece after it. */
    private fun paginate(all: List<Piece>, room: Float): List<List<Piece>> {
        val pages = mutableListOf<MutableList<Piece>>(mutableListOf())
        var used = 0f
        var i = 0
        while (i < all.size) {
            val group = if (all[i].keepWithNext && i + 1 < all.size) listOf(all[i], all[i + 1]) else listOf(all[i])
            val need = group.sumOf { it.height.toDouble() }.toFloat()
            if (used + need > room && pages.last().isNotEmpty()) { pages.add(mutableListOf()); used = 0f }
            pages.last().addAll(group)
            used += need
            i += group.size
        }
        return pages
    }

    private fun piecesFor(block: EmergencyKit.Block, width: Float): List<Piece> = when (block) {
        is EmergencyKit.Block.Title -> listOf(text(block.text, width, 22f, bold = true, after = 6f))
        is EmergencyKit.Block.Paragraph -> listOf(text(block.text, width, BODY, after = 10f))
        is EmergencyKit.Block.Fact -> listOf(fact(block.label, block.value, width))
        is EmergencyKit.Block.BlankLine -> listOf(blankLine(block.label, width))
        is EmergencyKit.Block.Heading -> listOf(text(block.text, width, 14f, bold = true, before = 14f, after = 6f, keepWithNext = true))
        is EmergencyKit.Block.PhraseBoxes -> listOf(boxes(block.boxes, width))
        is EmergencyKit.Block.Steps -> block.items.mapIndexed { i, s -> numbered(i + 1, s, width) }
        is EmergencyKit.Block.Warning -> listOf(warning(block.text, width))
    }

    private fun paint(size: Float, bold: Boolean = false, mono: Boolean = false) = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.BLACK
        textSize = size
        typeface = if (mono) Typeface.MONOSPACE else if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
    }

    /** Wrapping text (StaticLayout, so long translations wrap and CJK renders through the system fonts). */
    private fun layout(text: String, width: Float, p: TextPaint): StaticLayout =
        StaticLayout.Builder.obtain(text, 0, text.length, p, width.toInt().coerceAtLeast(1)).setLineSpacing(0f, 1.15f).build()

    private fun text(
        s: String, width: Float, size: Float, bold: Boolean = false, before: Float = 0f, after: Float = 0f, keepWithNext: Boolean = false,
    ): Piece {
        val l = layout(s, width, paint(size, bold))
        return Piece(before + l.height + after, keepWithNext) { c, y -> drawLayout(c, l, 0f, y + before) }
    }

    private fun drawLayout(c: Canvas, l: StaticLayout, x: Float, y: Float) {
        c.save(); c.translate(MARGIN + x, y); l.draw(c); c.restore()
    }

    private fun fact(label: String, value: String, width: Float): Piece {
        val labelWidth = width * 0.38f
        val a = layout(label, labelWidth - 8f, paint(BODY, bold = true))
        val b = layout(value, width - labelWidth, paint(BODY))
        return Piece(maxOf(a.height, b.height) + 3f) { c, y -> drawLayout(c, a, 0f, y); drawLayout(c, b, labelWidth, y) }
    }

    private fun blankLine(label: String, width: Float): Piece {
        val l = layout(label, width, paint(BODY))
        val line = Paint().apply { color = Color.BLACK; strokeWidth = 1f }
        return Piece(l.height + 30f) { c, y ->
            drawLayout(c, l, 0f, y + 14f)
            val ly = y + 14f + l.height + 18f
            c.drawLine(MARGIN, ly, MARGIN + width, ly, line)
        }
    }

    private fun boxes(boxes: List<EmergencyKit.Box>, width: Float): Piece {
        val columns = 4
        val gap = 6f
        val cell = (width - gap * (columns - 1)) / columns
        val height = 28f
        val rows = (boxes.size + columns - 1) / columns
        val stroke = Paint().apply { color = Color.BLACK; style = Paint.Style.STROKE; strokeWidth = 1f }
        val small = paint(8f)
        val word = paint(11f, mono = true)
        return Piece(rows * (height + gap)) { c, y ->
            for ((i, box) in boxes.withIndex()) {
                val x = MARGIN + ((i % columns) * (cell + gap))
                val top = y + ((i / columns) * (height + gap))
                c.drawRoundRect(x, top, x + cell, top + height, 3f, 3f, stroke)
                c.drawText(box.number.toString(), x + 4f, top + 18f, small)
                // A long word shrinks to fit rather than running out of its box.
                val avail = cell - 24f
                val w = word.measureText(box.word)
                word.textSize = if (w > avail && w > 0f) 11f * avail / w else 11f
                c.drawText(box.word, x + 20f, top + 18f, word)
            }
        }
    }

    private fun numbered(n: Int, s: String, width: Float): Piece {
        val indent = 18f
        val num = layout("$n.", indent, paint(BODY))
        val l = layout(s, width - indent, paint(BODY))
        return Piece(l.height + 4f) { c, y -> drawLayout(c, num, 0f, y); drawLayout(c, l, indent, y) }
    }

    private fun warning(s: String, width: Float): Piece {
        val pad = 8f
        val l = layout(s, width - 2 * pad, paint(BODY, bold = true))
        val frame = Paint().apply { color = Color.BLACK; style = Paint.Style.STROKE; strokeWidth = 1.5f }
        return Piece(l.height + 2 * pad + 12f) { c, y ->
            val top = y + 12f
            c.drawRect(MARGIN, top, MARGIN + width, top + l.height + 2 * pad, frame)
            drawLayout(c, l, pad, top + pad)
        }
    }

    private companion object {
        const val A4_WIDTH = 595f
        const val A4_HEIGHT = 842f
        const val MARGIN = 40f
        const val BODY = 11f
    }
}
