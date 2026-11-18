package app.localgatekeys.wear

import androidx.wear.protolayout.ActionBuilders
import androidx.wear.protolayout.ColorBuilders.argb
import androidx.wear.protolayout.DimensionBuilders.dp
import androidx.wear.protolayout.DimensionBuilders.expand
import androidx.wear.protolayout.DimensionBuilders.sp
import androidx.wear.protolayout.LayoutElementBuilders
import androidx.wear.protolayout.ModifiersBuilders

/**
 * One pinned code on the watch. [code] null: digits hidden (expired, or nothing valid since the phone was last in
 * reach); empty: the item gives no code (a dash). [validForMillis]: how long the digits stay valid. Never shows the code.
 */
class PinnedCode(val title: String, val code: String?, val validForMillis: Long = 0) {
    override fun toString(): String = "PinnedCode(shown=${code != null}, validForMillis=$validForMillis)"
}

/** What the store knows. */
sealed interface TileInput {
    /** No message from the phone yet. */
    data object NoData : TileInput

    /** The phone's vault locked (or was erased): no titles, no codes. */
    data class Locked(val immediately: Boolean) : TileInput

    /** The pinned codes as last sent, [ageSeconds] ago (empty: nothing pinned). */
    data class Known(val codes: List<PinnedCode>, val ageSeconds: Long) : TileInput
}

sealed interface Footer {
    data object NoData : Footer
    data object Locked : Footer
    data object LockedImmediately : Footer
    data object Empty : Footer
    data object WatchLocked : Footer
    data class Updated(val ageSeconds: Long) : Footer
}

/** A row as drawn: the digits (grouped, or a placeholder) and the title. */
data class TileRow(val title: String, val digits: String, val shown: Boolean) {
    override fun toString(): String = "TileRow(shown=$shown)"
}

data class TileModel(val rows: List<TileRow>, val footer: Footer)

/** The tile's words (string resources in the app, plain English in tests). */
interface TileTexts {
    fun noData(): String
    fun locked(): String
    fun lockedImmediately(): String
    fun empty(): String
    fun watchLocked(): String
    fun updatedNow(): String
    fun updatedMinutes(n: Long): String
    fun updatedHours(n: Long): String
    fun updatedDays(n: Long): String
}

object CodesTileLayout {
    const val HIDDEN = "••• •••"
    const val NO_CODE = "–"
    const val CLICK_REFRESH = "refresh"

    /** The rows and footer for [input]. A locked watch ([watchLocked]) never shows digits. */
    fun model(input: TileInput, watchLocked: Boolean = false): TileModel = when (input) {
        TileInput.NoData -> TileModel(emptyList(), Footer.NoData)
        is TileInput.Locked -> TileModel(emptyList(), if (input.immediately) Footer.LockedImmediately else Footer.Locked)
        is TileInput.Known -> {
            if (input.codes.isEmpty()) {
                TileModel(emptyList(), Footer.Empty)
            } else {
                val rows = input.codes.take(4).map { c ->
                    val code = c.code
                    when {
                        code == null || watchLocked -> TileRow(c.title, HIDDEN, shown = false)
                        code.isEmpty() -> TileRow(c.title, NO_CODE, shown = false)
                        else -> TileRow(c.title, group(code), shown = true)
                    }
                }
                TileModel(rows, if (watchLocked) Footer.WatchLocked else Footer.Updated(input.ageSeconds))
            }
        }
    }

    /** The model from pinned codes and their age (null codes: no data yet). */
    fun model(codes: List<PinnedCode>?, ageSeconds: Long, watchLocked: Boolean = false): TileModel =
        model(if (codes == null) TileInput.NoData else TileInput.Known(codes, ageSeconds), watchLocked)

    fun footerText(f: Footer, t: TileTexts): String = when (f) {
        Footer.NoData -> t.noData()
        Footer.Locked -> t.locked()
        Footer.LockedImmediately -> t.lockedImmediately()
        Footer.Empty -> t.empty()
        Footer.WatchLocked -> t.watchLocked()
        is Footer.Updated -> {
            val s = f.ageSeconds.coerceAtLeast(0)
            when {
                s <= 60 -> t.updatedNow()
                s < 3_600 -> t.updatedMinutes(s / 60)
                s < 172_800 -> t.updatedHours(s / 3_600)
                else -> t.updatedDays(s / 86_400)
            }
        }
    }

    /** "123456" -> "123 456", "12345678" -> "1234 5678". */
    fun group(code: String): String = when (code.length) {
        6 -> code.substring(0, 3) + " " + code.substring(3)
        8 -> code.substring(0, 4) + " " + code.substring(4)
        else -> code
    }

    /** The tile's layout. Tapping anywhere asks the phone again and redraws (a load action, nothing leaves the tile). */
    fun layout(model: TileModel, t: TileTexts): LayoutElementBuilders.LayoutElement {
        val column = LayoutElementBuilders.Column.Builder()
            .setWidth(expand())
            .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
        for (row in model.rows) {
            column.addContent(
                LayoutElementBuilders.Text.Builder()
                    .setText(row.digits + "  " + row.title)
                    .setMaxLines(1)
                    .setOverflow(LayoutElementBuilders.TEXT_OVERFLOW_ELLIPSIZE_END)
                    .setFontStyle(
                        LayoutElementBuilders.FontStyle.Builder()
                            .setSize(sp(if (model.rows.size > 2) 15f else 18f))
                            .setWeight(LayoutElementBuilders.FONT_WEIGHT_BOLD)
                            .setColor(argb(if (row.shown) 0xFFFFFFFF.toInt() else 0xFFB0B0B0.toInt()))
                            .build(),
                    )
                    .build(),
            )
            column.addContent(LayoutElementBuilders.Spacer.Builder().setHeight(dp(4f)).build())
        }
        column.addContent(
            LayoutElementBuilders.Text.Builder()
                .setText(footerText(model.footer, t))
                .setMaxLines(3)
                .setMultilineAlignment(LayoutElementBuilders.TEXT_ALIGN_CENTER)
                .setFontStyle(LayoutElementBuilders.FontStyle.Builder().setSize(sp(12f)).setColor(argb(0xFFB0B0B0.toInt())).build())
                .build(),
        )
        return LayoutElementBuilders.Box.Builder()
            .setWidth(expand())
            .setHeight(expand())
            .setModifiers(
                ModifiersBuilders.Modifiers.Builder()
                    .setPadding(ModifiersBuilders.Padding.Builder().setAll(dp(20f)).build())
                    .setClickable(
                        ModifiersBuilders.Clickable.Builder()
                            .setId(CLICK_REFRESH)
                            .setOnClick(ActionBuilders.LoadAction.Builder().build())
                            .build(),
                    )
                    .build(),
            )
            .addContent(column.build())
            .build()
    }
}
