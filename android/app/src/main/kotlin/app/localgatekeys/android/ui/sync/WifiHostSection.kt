package app.localgatekeys.android.ui.sync

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.android.i18n.rememberTxt
import app.localgatekeys.android.sync.HostPairing
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.sync.WifiHost
import app.localgatekeys.android.ui.common.qrBitmap
import app.localgatekeys.android.ui.shell.Overlay
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import app.localgatekeys.android.ui.theme.lgkSwitchColors
import app.localgatekeys.android.ui.theme.warningText
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import kotlinx.coroutines.launch

/** What the host's pairing sheet and card say for [note] (the Mac's `HostPairingModel` messages). */
internal fun hostNoteText(note: HostPairing.Note, state: HostPairing.State, words: SyncWording, t: Txt): String = when (note) {
    HostPairing.Note.COPIED -> t.s(R.string.sync_host_copied)
    HostPairing.Note.CLOSED -> t.s(R.string.sync_host_closed)
    HostPairing.Note.NOT_WAITING -> t.s(R.string.sync_host_not_waiting)
    HostPairing.Note.DECLINED -> t.s(R.string.sync_host_declined)
    HostPairing.Note.ADDING -> t.s(R.string.sync_host_adding, words.sanitize(state.request?.name ?: ""))
    HostPairing.Note.STEP_FAILED -> words.stepFailedText
    HostPairing.Note.TOO_MANY_PEERS -> words.errorText("too-many-peers")
}

/** "Paired: <name · Device id> (key …). If you don't recognise it, choose Undo." */
internal fun hostPairedText(p: HostPairing.Paired, words: SyncWording, t: Txt): String {
    val name = words.deviceLabel(p.deviceId, mapOf(p.deviceId to p.name))
    val undo = t.s(R.string.sync_host_undo_hint)
    return if (p.fingerprint.isEmpty()) t.s(R.string.sync_host_paired_plain, name, undo) else t.s(R.string.sync_host_paired_key, name, p.fingerprint, undo)
}

/**
 * The Wi-Fi card's host part (the Mac's Sync page): "Host Wi-Fi sync on this phone", where it listens (or why not),
 * Show QR code (the pairing sheet), Undo / Keep after a device was added, and the devices paired with this phone.
 */
@Composable
internal fun ColumnScope.WifiHostSection(host: WifiHost, membership: SyncCoordinator.Membership, busy: Boolean, onShowSheet: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val words = remember(txt) { SyncWording(txt) }
    val status by host.status.collectAsStateWithLifecycle()
    val pairing by host.pairing.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var removing by remember { mutableStateOf<String?>(null) }

    HorizontalDivider(thickness = 0.5.dp, color = c.separator)
    Row(
        Modifier.fillMaxWidth().heightIn(min = 44.dp).testTag("sync-host-toggle")
            .toggleable(status.enabled, role = Role.Switch, onValueChange = { host.setEnabled(it) }),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(txt.s(R.string.sync_host_toggle), color = c.text, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(status.enabled, onCheckedChange = null, colors = lgkSwitchColors())
    }
    Footnote(txt.s(R.string.sync_host_intro))
    if (status.enabled) {
        val endpoint = status.endpoint
        if (status.listening && endpoint != null) {
            val at = txt.s(R.string.sync_host_port, endpoint.host, endpoint.port)
            Text(
                if (status.followed) txt.s(R.string.sync_host_followed, at) else txt.s(R.string.sync_host_listens, at),
                color = c.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("sync-host-listening"),
            )
        }
        status.problem?.let { p ->
            val text = when (p) {
                WifiHost.Problem.NO_WIFI -> txt.s(R.string.sync_host_no_wifi)
                WifiHost.Problem.COULD_NOT_LISTEN -> txt.s(R.string.sync_host_could_not_listen)
                WifiHost.Problem.STOPPED -> txt.s(R.string.sync_host_stopped)
                WifiHost.Problem.NOT_LISTENING -> txt.s(R.string.sync_host_not_listening)
            }
            Text(text, color = c.warningText, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("sync-host-problem"))
        }
        if (status.licenceOnly) Footnote(txt.s(R.string.sync_host_free))
        status.showError?.let { reason ->
            Text(if (reason.isEmpty()) words.stepFailedText else words.errorText(reason), color = c.danger, style = MaterialTheme.typography.bodyMedium)
        }
        ActionButton(txt.s(R.string.sync_host_show_qr), enabled = !busy) {
            scope.launch { if (host.showQr() == WifiHost.ShowResult.SHOWN) onShowSheet() }
        }
    }
    val paired = pairing.paired
    if (pairing.stage == HostPairing.Stage.PAIRED && paired != null) {
        Text(hostPairedText(paired, words, txt), color = c.text, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("sync-host-paired"))
        ActionButton(txt.s(R.string.sync_host_undo), destructive = true) { scope.launch { host.undo() } }
        ActionButton(txt.s(R.string.sync_host_keep)) { host.pairing.keep() }
    }
    val peers = membership.lanPeers.filter { !it.revoked }
    if (status.enabled || peers.isNotEmpty()) {
        HorizontalDivider(thickness = 0.5.dp, color = c.separator)
        Text(
            txt.s(R.string.sync_host_paired_heading), color = c.secondaryText, style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(top = 6.dp).semantics { heading() },
        )
        if (peers.isEmpty()) Footnote(txt.s(R.string.sync_host_no_peers))
        for (peer in peers) {
            Row(Modifier.fillMaxWidth().heightIn(min = 44.dp).testTag("sync-host-peer-${peer.deviceId}"), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    words.deviceLabel(peer.deviceId, mapOf(peer.deviceId to peer.name)), color = c.text,
                    style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f).padding(vertical = 6.dp),
                )
                TextButton({ removing = peer.deviceId }, enabled = !busy) {
                    Text(txt.s(R.string.sync_host_remove), color = if (busy) c.secondaryText else c.danger)
                }
            }
        }
    }
    removing?.let { id ->
        val name = words.deviceLabel(id, mapOf(id to membership.lanPeers.firstOrNull { it.deviceId == id }?.name))
        AlertDialog(
            onDismissRequest = { removing = null },
            text = { Text(txt.s(R.string.sync_host_remove_confirm, name)) },
            confirmButton = {
                TextButton({
                    removing = null
                    scope.launch { host.remove(id) }
                }) { Text(txt.s(R.string.sync_remove_button), color = c.danger) }
            },
            dismissButton = { TextButton({ removing = null }) { Text(stringResource(R.string.common_cancel), color = c.accentText) } },
        )
    }
}

/** The pairing sheet (the Mac's QR sheet): QR code and code text, then the joining device for Accept or Decline. */
@Composable
internal fun HostPairingSheet(host: WifiHost, onClose: () -> Unit) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val words = remember(txt) { SyncWording(txt) }
    val state by host.pairing.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val close = {
        host.closePairing()
        onClose()
    }
    BackHandler(onBack = close)
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("host-pairing")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(close) { Text(stringResource(R.string.common_close), color = c.accentText) }
                Text(
                    txt.s(R.string.sync_host_show_qr), color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                Box(Modifier.size(64.dp))
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Column(
                    Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    when (state.stage) {
                        HostPairing.Stage.SHOWING, HostPairing.Stage.EXPIRED -> OfferPart(host, state)
                        HostPairing.Stage.CONFIRM -> ConfirmPart(host, state, words)
                        HostPairing.Stage.ADDING -> {
                            CircularProgressIndicator(Modifier.size(24.dp), color = c.secondaryText, strokeWidth = 2.dp)
                            Text(txt.s(R.string.sync_host_adding_button), color = c.text, style = MaterialTheme.typography.bodyLarge)
                        }
                        HostPairing.Stage.PAIRED -> state.paired?.let { p ->
                            Text(
                                txt.s(R.string.sync_host_paired_title, words.deviceLabel(p.deviceId, mapOf(p.deviceId to p.name))),
                                color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center,
                            )
                            Text(hostPairedText(p, words, txt), color = c.text, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
                            SheetButton(txt.s(R.string.sync_host_undo), destructive = true) { scope.launch { if (host.undo()) onClose() } }
                            SheetButton(txt.s(R.string.sync_host_keep)) { host.pairing.keep(); close() }
                        }
                        HostPairing.Stage.DECLINED, HostPairing.Stage.IDLE -> {
                            SheetButton(txt.s(R.string.sync_host_show_qr)) { scope.launch { host.showQr() } }
                        }
                    }
                    state.note?.let { note ->
                        Text(
                            hostNoteText(note, state, words, txt), color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center, modifier = Modifier.testTag("host-pairing-note"),
                        )
                    }
                }
                Text(txt.s(R.string.sync_host_pair_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
            }
        }
    }
}

@Composable
private fun OfferPart(host: WifiHost, state: HostPairing.State) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val scope = rememberCoroutineScope()
    val qr = state.qrText
    val expired = state.stage == HostPairing.Stage.EXPIRED || (state.expiresIn ?: 0) <= 0
    Text(
        txt.s(R.string.sync_host_scan_title), color = c.text, style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center,
    )
    // The image is made while the code is open and dropped with it (the code text is the pairing secret).
    val image = remember(qr) { qr?.let { qrBitmap(it, 720, ErrorCorrectionLevel.M) } }
    if (image != null && !expired) {
        val description = txt.s(R.string.sync_host_qr_description)
        Image(
            image, description, filterQuality = FilterQuality.None,
            modifier = Modifier.size(260.dp).background(Color.White).padding(8.dp).testTag("host-pairing-qr"),
        )
    }
    state.offerCode?.let {
        Text(
            txt.s(R.string.sync_host_code, it), color = c.text,
            style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace), modifier = Modifier.testTag("host-pairing-code"),
        )
    }
    Text(
        if (expired) txt.s(R.string.sync_host_expired) else txt.s(R.string.sync_host_expires_in, HostPairing.clock(state.expiresIn ?: 0)),
        color = c.secondaryText, style = MaterialTheme.typography.bodyMedium,
    )
    if (expired) {
        SheetButton(txt.s(R.string.sync_host_show_qr)) { scope.launch { host.showQr() } }
    } else {
        SheetButton(txt.s(R.string.sync_host_copy_code)) { host.copyCode() }
        Text(txt.s(R.string.sync_host_other_pc_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
    }
}

@Composable
private fun ConfirmPart(host: WifiHost, state: HostPairing.State, words: SyncWording) {
    val txt = rememberTxt()
    val c = LgkTheme.colors
    val r = state.request ?: return
    val name = words.sanitize(r.name)
    Text(
        txt.s(R.string.sync_host_add_named, name), color = c.text, style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center,
    )
    Text(txt.s(R.string.sync_host_confirm, name, r.code), color = c.text, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
    Text(
        r.code, color = c.text,
        style = MaterialTheme.typography.displaySmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold),
        modifier = Modifier.testTag("host-pairing-request-code"),
    )
    if (r.fingerprint.isNotEmpty()) {
        Text(txt.s(R.string.sync_host_fingerprint, r.fingerprint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall)
    }
    state.secondsLeft?.let { Text(txt.s(R.string.sync_host_declines_in, it), color = c.secondaryText, style = MaterialTheme.typography.bodySmall) }
    Text(txt.s(R.string.sync_host_accept_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
    Text(txt.s(R.string.sync_host_decline_hint), color = c.secondaryText, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
    SheetButton(txt.s(R.string.sync_host_accept), primary = true) { host.pairing.decide(true, r.deviceId) }
    SheetButton(txt.s(R.string.sync_host_decline), destructive = true) { host.pairing.decide(false, r.deviceId) }
}

@Composable
private fun SheetButton(label: String, primary: Boolean = false, destructive: Boolean = false, onClick: () -> Unit) {
    val c = LgkTheme.colors
    if (primary) {
        Button(
            onClick, colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(label, fontWeight = FontWeight.SemiBold) }
    } else {
        TextButton(onClick, modifier = Modifier.fillMaxWidth()) { Text(label, color = if (destructive) c.danger else c.accentText) }
    }
}

/** The pairing sheet over the whole screen while [open]. */
@Composable
internal fun HostPairingOverlay(host: WifiHost, open: Boolean, onClose: () -> Unit) {
    if (open) Overlay { HostPairingSheet(host, onClose) }
}
