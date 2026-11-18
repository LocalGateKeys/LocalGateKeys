package app.localgatekeys.android.ui.security

import android.content.Context
import android.content.ContextWrapper
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.security.HealthReport
import java.io.FileOutputStream

/**
 * Prints the one-page vault health report (A4) through the system print UI, which also offers "Save as PDF" and
 * sharing (the same path as the emergency kit). Only non-secret facts are drawn.
 */
object HealthReportPrint {
    fun print(context: Context, txt: Txt, facts: HealthReport.Facts) {
        val activity = generateSequence(context) { (it as? ContextWrapper)?.baseContext }.firstOrNull { it is android.app.Activity } ?: return
        val manager = activity.getSystemService(Context.PRINT_SERVICE) as? PrintManager ?: return
        val title = txt.s(R.string.health_report_title)
        val rows = HealthReport.rows(facts, txt)
        val attrs = PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build()
        manager.print(title, ReportAdapter(title, rows, txt.s(R.string.health_report_no_secrets)), attrs)
    }

    /** Draws the report on one A4 page of [doc] (595 x 842 points). */
    fun draw(doc: PdfDocument, title: String, rows: List<Pair<String, String>>, footer: String) {
        val page = doc.startPage(PdfDocument.PageInfo.Builder(A4_W, A4_H, 0).create())
        val c = page.canvas
        val bold = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.BLACK; typeface = Typeface.DEFAULT_BOLD; textSize = 10f }
        val plain = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = Color.BLACK; textSize = 10f }
        c.drawText(title, 56f, 72f, Paint(bold).apply { textSize = 16f })
        var y = 110f
        for ((label, value) in rows.take(MAX_ROWS)) {
            c.drawText(label, 56f, y, bold)
            c.drawText(value.take(70), 230f, y, plain)
            y += 20f
        }
        c.drawText(footer, 56f, y + 20f, Paint(plain).apply { textSize = 9f })
        doc.finishPage(page)
    }

    private const val A4_W = 595
    private const val A4_H = 842
    private const val MAX_ROWS = 40
}

private class ReportAdapter(private val title: String, private val rows: List<Pair<String, String>>, private val footer: String) : PrintDocumentAdapter() {
    override fun onLayout(
        oldAttributes: PrintAttributes?, newAttributes: PrintAttributes, cancellationSignal: CancellationSignal?,
        callback: LayoutResultCallback, extras: Bundle?,
    ) {
        if (cancellationSignal?.isCanceled == true) { callback.onLayoutCancelled(); return }
        callback.onLayoutFinished(
            PrintDocumentInfo.Builder(title).setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(1).build(),
            oldAttributes != newAttributes,
        )
    }

    override fun onWrite(pages: Array<out PageRange>, destination: ParcelFileDescriptor, cancellationSignal: CancellationSignal?, callback: WriteResultCallback) {
        val doc = PdfDocument()
        try {
            HealthReportPrint.draw(doc, title, rows, footer)
            FileOutputStream(destination.fileDescriptor).use { doc.writeTo(it) }
            callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
        } catch (e: Exception) {
            callback.onWriteFailed(null)
        } finally {
            doc.close()
        }
    }
}
