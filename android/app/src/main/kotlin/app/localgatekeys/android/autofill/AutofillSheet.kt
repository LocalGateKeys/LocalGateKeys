package app.localgatekeys.android.autofill

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.localgatekeys.android.R
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface

/**
 * The autofill and save sheets in the Glass skin: the screen background with the sheet anchored at the bottom (top
 * corners rounded, a grab handle), solid surfaces only (text never sits on glass). Increased contrast: a 1.5 dp border.
 */
@Composable
internal fun AutofillSheet(content: @Composable ColumnScope.() -> Unit) {
    val c = LgkTheme.colors
    val shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp)
    Box(Modifier.fillMaxSize().background(c.background)) {
        Column(
            Modifier.align(Alignment.BottomCenter).fillMaxWidth()
                .background(c.groupSurface, shape)
                .border(BorderStroke(if (LgkTheme.increasedContrast) 1.5.dp else 0.5.dp, c.glassBorder), shape)
                .safeDrawingPadding()
                .padding(horizontal = 20.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(Modifier.align(Alignment.CenterHorizontally).width(36.dp).height(4.dp).background(c.separator, RoundedCornerShape(2.dp)))
            content()
        }
    }
}

/** App mark, title and the target line. */
@Composable
internal fun SheetHeader(title: String, subtitle: String?) {
    val c = LgkTheme.colors
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Image(painterResource(R.drawable.brand_mark), contentDescription = null, modifier = Modifier.size(40.dp))
        Column {
            Text(title, color = c.text, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            if (!subtitle.isNullOrEmpty()) {
                Text(subtitle, color = c.secondaryText, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/** A 22 dp group card on the sheet: the inner tile colour so it reads apart from the sheet surface. */
@Composable
internal fun SheetCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val c = LgkTheme.colors
    val shape = RoundedCornerShape(22.dp)
    Column(
        modifier.fillMaxWidth().lgkGroupSurface(22.dp).background(c.innerTile, shape)
            .then(if (LgkTheme.increasedContrast) Modifier.border(1.5.dp, c.glassBorder, shape) else Modifier)
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

/** A letter tile, a title and a username line. */
@Composable
internal fun LoginLine(row: FillPickerOrder.Row, modifier: Modifier = Modifier, trailing: @Composable (() -> Unit)? = null) {
    val c = LgkTheme.colors
    Row(modifier.heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.size(36.dp).background(c.accent.copy(alpha = 0.16f), RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) {
            Text(FillPickerOrder.initial(row), color = c.accentText, fontWeight = FontWeight.SemiBold)
        }
        Column(Modifier.weight(1f)) {
            Text(row.title.ifEmpty { row.username }, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (row.title.isNotEmpty() && row.username.isNotEmpty()) {
                Text(row.username, color = c.secondaryText, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
        trailing?.invoke()
    }
}

/** "Matches this site": a success-tinted capsule. */
@Composable
internal fun MatchTag(text: String) {
    val c = LgkTheme.colors
    Text(
        text, color = c.success, style = MaterialTheme.typography.labelMedium,
        modifier = Modifier.background(c.success.copy(alpha = 0.14f), RoundedCornerShape(50)).padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

@Composable
internal fun AccentButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val c = LgkTheme.colors
    Button(
        onClick = onClick, enabled = enabled,
        colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
        shape = RoundedCornerShape(14.dp),
        modifier = modifier.heightIn(min = 48.dp),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

@Composable
internal fun SheetTextButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier) {
    TextButton(onClick = onClick, modifier = modifier.heightIn(min = 48.dp)) { Text(text, color = LgkTheme.colors.accentText) }
}

@Composable
internal fun SectionLabel(text: String) {
    Text(text, color = LgkTheme.colors.secondaryText, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(start = 4.dp))
}

@Composable
internal fun sheetFieldColors(): TextFieldColors {
    val c = LgkTheme.colors
    return OutlinedTextFieldDefaults.colors(
        focusedBorderColor = c.accent, unfocusedBorderColor = if (LgkTheme.increasedContrast) c.secondaryText else c.separator,
        focusedLabelColor = c.accentText, unfocusedLabelColor = c.secondaryText, cursorColor = c.accent,
        focusedTextColor = c.text, unfocusedTextColor = c.text,
        focusedContainerColor = c.groupSurface, unfocusedContainerColor = c.groupSurface,
    )
}
