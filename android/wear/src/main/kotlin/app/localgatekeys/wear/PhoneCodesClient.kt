package app.localgatekeys.wear

import android.content.Context
import android.os.SystemClock
import androidx.wear.tiles.TileService
import app.localgatekeys.core.wear.WearCodes
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Sub-plan 06: the watch side of the Data Layer. [requestCodes] asks the phone for the current state; [Listener]
 * receives the phone's messages. Only nearby nodes (the paired phone over Bluetooth or Wi-Fi, never the cloud relay)
 * are asked or listened to, and the Data Layer itself delivers only this app's own phone app (same package and key).
 */
object PhoneCodesClient {
    private val lastAsk = AtomicLong(Long.MIN_VALUE / 2)

    /** Asks the phone for the current codes (at most every few seconds). Asynchronous; nothing is sent but the path. */
    fun requestCodes(context: Context) {
        val now = SystemClock.elapsedRealtime()
        val prev = lastAsk.get()
        if (now - prev < MIN_ASK_INTERVAL_MILLIS || !lastAsk.compareAndSet(prev, now)) return
        val app = context.applicationContext
        Wearable.getCapabilityClient(app).getCapability(WearCodes.CAPABILITY_PHONE, CapabilityClient.FILTER_REACHABLE)
            .addOnSuccessListener { info ->
                val messages = Wearable.getMessageClient(app)
                info.nodes.filter { it.isNearby }.forEach { node -> messages.sendMessage(node.id, WearCodes.PATH_REQUEST, ByteArray(0)) }
            }
    }

    /** True when [nodeId] is a nearby connected node. Blocking (a listener thread). */
    internal fun isNearby(context: Context, nodeId: String): Boolean = try {
        Tasks.await(Wearable.getNodeClient(context).connectedNodes, 5, TimeUnit.SECONDS).any { it.id == nodeId && it.isNearby }
    } catch (e: Exception) {
        false
    }

    private const val MIN_ASK_INTERVAL_MILLIS = 5_000L

    /**
     * The phone's messages on [WearCodes.PATH_CODES]. Exported because Google Play services binds it (the base class
     * accepts only Play services as the caller). A replace from a node that is not nearby is dropped; a forget is
     * always applied (it only removes). Anything malformed is dropped. Nothing is logged.
     */
    class Listener : WearableListenerService() {
        override fun onMessageReceived(event: MessageEvent) {
            if (event.path != WearCodes.PATH_CODES) return
            val message = WearCodes.decode(event.data ?: return) ?: return
            if (message is WearCodes.Replace && !isNearby(this, event.sourceNodeId)) return
            if (WatchCodesStore.of(this).apply(message)) {
                TileService.getUpdater(this).requestUpdate(CodesTileService::class.java)
            }
        }
    }
}
