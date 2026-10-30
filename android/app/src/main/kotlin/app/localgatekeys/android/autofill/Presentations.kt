package app.localgatekeys.android.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.InlinePresentation
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import app.localgatekeys.android.R

/** The rows autofill shows: a dropdown row, and on API 30+ a keyboard chip. Titles and usernames only. */
object Presentations {
    fun row(context: Context, title: String, subtitle: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle ?: "")
        }

    @SuppressLint("RestrictedApi")
    @RequiresApi(30)
    fun chip(context: Context, spec: InlinePresentationSpec, title: String, subtitle: String?): InlinePresentation? {
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
        // The long-press attribution: opens the app (no extras, immutable).
        val attribution = PendingIntent.getActivity(
            context, 0, Intent(context, app.localgatekeys.android.MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(title)
            .setStartIcon(Icon.createWithResource(context, R.mipmap.ic_launcher))
        if (!subtitle.isNullOrEmpty()) content.setSubtitle(subtitle)
        return InlinePresentation(content.build().slice, spec, false)
    }

    /** An authenticated dataset: no values until [auth] (our sheet) returns the filled one. */
    @Suppress("DEPRECATION")
    fun locked(fields: List<AutofillId>, row: RemoteViews, chip: InlinePresentation?, auth: PendingIntent): Dataset {
        val b = Dataset.Builder(row)
        for (id in fields) {
            if (chip != null && Build.VERSION.SDK_INT >= 30) b.setValue(id, null, row, chip) else b.setValue(id, null, row)
        }
        b.setAuthentication(auth.intentSender)
        return b.build()
    }

    /** The filled dataset our sheet returns ([EXTRA_AUTHENTICATION_RESULT]). */
    @Suppress("DEPRECATION")
    fun filled(row: RemoteViews, usernames: List<AutofillId>, passwords: List<AutofillId>, username: String, password: String): Dataset {
        val b = Dataset.Builder(row)
        for (id in usernames) b.setValue(id, AutofillValue.forText(username))
        for (id in passwords) b.setValue(id, AutofillValue.forText(password))
        return b.build()
    }
}
