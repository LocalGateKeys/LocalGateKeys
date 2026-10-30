package app.localgatekeys.android.autofill

import app.localgatekeys.android.R
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import app.localgatekeys.android.LgkApp
import java.util.concurrent.atomic.AtomicInteger

/**
 * The autofill service (spec section 5). It reads only the sealed fill index (titles, usernames, URL rows) and never
 * a secret: every dataset is authenticated through [FillAuthActivity], which unlocks and fills. Save requests hand
 * what was typed to [SaveLoginActivity] through [PendingSaves] (in process; the Intent carries a token).
 */
class LgkAutofillService : AutofillService() {
    private val app: LgkApp get() = application as LgkApp

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val response = try {
            respond(request)
        } catch (e: Exception) {
            null // never crash the requesting app's fill; no detail is logged
        }
        callback.onSuccess(response)
    }

    private fun respond(request: FillRequest): FillResponse? {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return null
        val form = FormParser.parse(StructureReader.nodes(structure))
        if (form.passwords.isEmpty() && form.usernames.isEmpty()) return null
        val pkg = structure.activityComponent.packageName
        val target = FillTarget.of(pkg, Signatures.of(this, pkg), form.webDomain, form.webScheme, packageName, app.privilegedBrowsers)
            ?: return null
        val fields: List<AutofillId> = form.usernames + form.passwords
        val index = app.fillIndex.read()
        val matches = if (app.settings.autofillSuggestions && index != null) FillMatcher(app.urlMatcher).match(index, target).take(MAX) else emptyList()

        val specs = if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.inlinePresentationSpecs ?: emptyList() else emptyList()
        val maxChips = if (Build.VERSION.SDK_INT >= 30) request.inlineSuggestionsRequest?.maxSuggestionCount ?: 0 else 0
        val b = FillResponse.Builder()
        var n = 0
        fun add(title: String, subtitle: String?, itemId: String?) {
            val chip = if (Build.VERSION.SDK_INT >= 30 && specs.isNotEmpty() && n < maxChips) {
                Presentations.chip(this, specs[minOf(n, specs.size - 1)], title, subtitle)
            } else {
                null
            }
            val intent = FillAuthActivity.intent(this, target, itemId, form.usernames, form.passwords)
            val pi = PendingIntent.getActivity(this, codes.incrementAndGet(), intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE)
            b.addDataset(Presentations.locked(fields, Presentations.row(this, title, subtitle), chip, pi))
            n++
        }
        for (m in matches) add(m.title.ifEmpty { m.username }, m.username.takeIf { it.isNotEmpty() && m.title.isNotEmpty() }, m.id)
        add(getString(if (app.settings.autofillSuggestions && index != null) R.string.autofill_search_lgk else R.string.main_unlock_localgatekeys), null, null)
        if (form.passwords.isNotEmpty()) {
            var type = SaveInfo.SAVE_DATA_TYPE_PASSWORD
            if (form.usernames.isNotEmpty()) type = type or SaveInfo.SAVE_DATA_TYPE_USERNAME
            val save = SaveInfo.Builder(type, form.passwords.toTypedArray())
                .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            if (form.usernames.isNotEmpty()) save.setOptionalIds(form.usernames.toTypedArray())
            b.setSaveInfo(save.build())
        }
        return b.build()
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        try {
            val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess()
            val form = FormParser.parse(StructureReader.nodes(structure))
            val password = form.passwords.firstNotNullOfOrNull { StructureReader.text(structure, it)?.takeIf { p -> p.isNotEmpty() } }
                ?: return callback.onSuccess()
            val username = form.usernames.firstNotNullOfOrNull { StructureReader.text(structure, it)?.trim()?.takeIf { u -> u.isNotEmpty() } } ?: ""
            val pkg = structure.activityComponent.packageName
            val target = FillTarget.of(pkg, Signatures.of(this, pkg), form.webDomain, form.webScheme, packageName, app.privilegedBrowsers)
                ?: return callback.onSuccess()
            val token = PendingSaves.put(target, username, password)
            val intent = Intent(this, SaveLoginActivity::class.java).putExtra(SaveLoginActivity.TOKEN, token)
            val pi = PendingIntent.getActivity(this, codes.incrementAndGet(), intent, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            callback.onSuccess(pi.intentSender)
        } catch (e: Exception) {
            callback.onSuccess()
        }
    }

    companion object {
        private const val MAX = 5
        private val codes = AtomicInteger(1000)
    }
}
