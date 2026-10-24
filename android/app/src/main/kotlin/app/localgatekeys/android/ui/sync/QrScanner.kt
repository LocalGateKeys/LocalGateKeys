package app.localgatekeys.android.ui.sync

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.localgatekeys.android.ui.theme.AuroraBackground
import app.localgatekeys.android.ui.theme.GlassBackdropHost
import app.localgatekeys.android.ui.theme.LgkTheme
import app.localgatekeys.android.ui.theme.lgkGroupSurface
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** The camera permission as the scanner sees it (seam: device tests deny it without a system dialog). */
interface CameraPermission {
    fun isGranted(): Boolean

    /** Asks once (the system dialog); [onResult] gets the answer. */
    fun request(onResult: (Boolean) -> Unit)

    /** Opens this app's page in the system settings, where the camera can be allowed. */
    fun openSettings()

    /** False when the phone has no camera at all (nothing to ask for). */
    fun hasCamera(): Boolean
}

/** Tests provide a fake; null: the real permission of the activity. */
val LocalCameraPermission = staticCompositionLocalOf<CameraPermission?> { null }

object QrScanner {
    /** The app's page in the system settings (Settings › Apps › LocalGateKeys). */
    fun appSettingsIntent(packageName: String): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /** Ruling 19: shown in the Sync tab when the camera permission is off (Open Settings goes to the app's page). */
    const val SYNC_DENIED_TEXT =
        "LocalGateKeys is not allowed to use the camera, so it cannot scan the code. In Settings, tap Permissions, then " +
            "Camera, and choose Allow. Then scan the code again, or use Paste code text instead."

    /** Ruling 19: shown in the 2FA scanner when the camera permission is off. */
    const val TOTP_DENIED_TEXT =
        "LocalGateKeys is not allowed to use the camera, so it cannot scan the code. In Settings, tap Permissions, then " +
            "Camera, and choose Allow. Then scan the code again, or paste the setup key instead."

    /**
     * Reads a QR code from one camera frame's luminance plane (Y of YUV_420_888: [rowStride] bytes per row). Null when
     * the frame holds no readable QR code. Nothing is kept: the frame stays in memory only while it is read.
     */
    fun decode(luminance: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
        if (width <= 0 || height <= 0 || rowStride < width || luminance.size < rowStride * (height - 1) + width) return null
        return try {
            val source = PlanarYUVLuminanceSource(luminance, rowStride, height, 0, 0, width, height, false)
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), HINTS).text
        } catch (_: ReaderException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private val HINTS = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
    )
}

private class ActivityCameraPermission(
    private val context: Context,
    private val ask: (onResult: (Boolean) -> Unit) -> Unit,
) : CameraPermission {
    override fun isGranted(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    override fun request(onResult: (Boolean) -> Unit) = ask(onResult)

    override fun openSettings() {
        try {
            context.startActivity(QrScanner.appSettingsIntent(context.packageName))
        } catch (_: Exception) {
        }
    }

    override fun hasCamera(): Boolean = context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
}

@Composable
private fun rememberCameraPermission(): CameraPermission {
    LocalCameraPermission.current?.let { return it }
    val context = LocalContext.current
    var pending by remember { mutableStateOf<((Boolean) -> Unit)?>(null) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        pending?.invoke(granted)
        pending = null
    }
    return remember(context, launcher) {
        ActivityCameraPermission(context) { onResult ->
            pending = onResult
            launcher.launch(Manifest.permission.CAMERA)
        }
    }
}

/**
 * The camera QR scanner (from `ios/App/Sync/QRScanner.swift`), full screen with [title] and Cancel. The camera
 * permission is asked when this opens (the person tapped scan), never earlier. It reports the first QR text it reads,
 * once ([onCode]); no camera or a camera that fails to start -> [onUnavailable]. A refused permission shows
 * [deniedText] and a button to the app's system settings (spec section 7); coming back with it allowed starts the camera.
 * Frames are read in memory and dropped; nothing is saved and nothing leaves the phone.
 */
@Composable
fun QrScannerScreen(
    title: String,
    deniedText: String,
    onCode: (String) -> Unit,
    onUnavailable: () -> Unit,
    onCancel: () -> Unit,
) {
    val c = LgkTheme.colors
    val permission = rememberCameraPermission()
    // null: not known yet (asking).
    var granted by remember { mutableStateOf<Boolean?>(if (permission.isGranted()) true else null) }
    val unavailable by rememberUpdatedState(onUnavailable)
    LaunchedEffect(permission) {
        when {
            !permission.hasCamera() -> unavailable()
            granted == null -> permission.request { granted = it }
        }
    }
    // Back from the system settings with the camera allowed: start it.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle, permission) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && granted == false && permission.isGranted()) granted = true
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    BackHandler(onBack = onCancel)
    // Takes every touch, so none reaches the screen underneath.
    Box(Modifier.fillMaxSize().pointerInput(Unit) { awaitPointerEventScope { while (true) awaitPointerEvent() } }.testTag("qr-scanner")) {
        GlassBackdropHost(Modifier.fillMaxSize()) { AuroraBackground() }
        Column(Modifier.fillMaxSize().statusBarsPadding()) {
            Row(Modifier.fillMaxWidth().height(64.dp).padding(horizontal = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                TextButton(onCancel) { Text("Cancel", color = c.accentText) }
                Text(
                    title, color = c.text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center, modifier = Modifier.weight(1f).semantics { heading() },
                )
                // Balances the Cancel button so the title stays centred (invisible, not a control).
                TextButton({}, enabled = false, modifier = Modifier.clearAndSetSemantics {}) { Text("Cancel", color = Color.Transparent) }
            }
            when (granted) {
                true -> CameraPreview(onCode, onUnavailable, Modifier.fillMaxSize().background(Color.Black))
                false -> Column(
                    Modifier.fillMaxSize().verticalScroll(rememberScrollState()).navigationBarsPadding().padding(16.dp),
                ) {
                    Column(
                        Modifier.fillMaxWidth().lgkGroupSurface().padding(16.dp).testTag("camera-denied"),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Text(deniedText, color = c.text, style = MaterialTheme.typography.bodyLarge)
                        Button(
                            { permission.openSettings() },
                            colors = ButtonDefaults.buttonColors(containerColor = c.accent, contentColor = Color.White),
                        ) { Text("Open Settings", fontWeight = FontWeight.SemiBold) }
                    }
                }
                null -> Box(Modifier.fillMaxSize())
            }
        }
    }
}

/** CameraX preview plus a ZXing analyser on a background thread; the first QR text read goes to [onCode] on the main thread. */
@Composable
private fun CameraPreview(onCode: (String) -> Unit, onUnavailable: () -> Unit, modifier: Modifier) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val code by rememberUpdatedState(onCode)
    val unavailable by rememberUpdatedState(onUnavailable)
    val reported = remember { AtomicBoolean(false) }
    val executor: ExecutorService = remember { Executors.newSingleThreadExecutor() }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    DisposableEffect(Unit) {
        onDispose {
            reported.set(true)
            try { provider?.unbindAll() } catch (_: Exception) { }
            executor.shutdown()
        }
    }
    AndroidView(
        modifier = modifier.testTag("camera-preview"),
        factory = { ctx ->
            PreviewView(ctx).also { view ->
                val future = ProcessCameraProvider.getInstance(ctx)
                future.addListener({
                    try {
                        val p = future.get()
                        val selector = when {
                            p.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA) -> CameraSelector.DEFAULT_BACK_CAMERA
                            p.hasCamera(CameraSelector.DEFAULT_FRONT_CAMERA) -> CameraSelector.DEFAULT_FRONT_CAMERA
                            else -> null
                        }
                        if (selector == null || reported.get()) {
                            if (selector == null) unavailable()
                            return@addListener
                        }
                        val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        val main = ContextCompat.getMainExecutor(context)
                        analysis.setAnalyzer(executor) { image -> analyse(image, reported) { text -> main.execute { code(text) } } }
                        p.unbindAll()
                        p.bindToLifecycle(owner, selector, preview, analysis)
                        provider = p
                    } catch (_: Exception) {
                        unavailable()
                    }
                }, ContextCompat.getMainExecutor(ctx))
            }
        },
    )
}

private fun analyse(image: ImageProxy, reported: AtomicBoolean, report: (String) -> Unit) {
    try {
        if (reported.get()) return
        val plane = image.planes.firstOrNull() ?: return
        val buffer = plane.buffer
        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }
        val text = QrScanner.decode(bytes, image.width, image.height, plane.rowStride)
        bytes.fill(0)
        if (text != null && reported.compareAndSet(false, true)) report(text)
    } catch (_: Exception) {
    } finally {
        image.close()
    }
}
