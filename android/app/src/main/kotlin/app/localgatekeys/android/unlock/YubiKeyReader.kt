package app.localgatekeys.android.unlock

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import app.localgatekeys.core.crypto.CompositeKey
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.BadResponseException
import com.yubico.yubikit.core.application.TimeoutException
import com.yubico.yubikit.core.otp.CommandRejectedException
import com.yubico.yubikit.yubiotp.Slot
import com.yubico.yubikit.yubiotp.YubiOtpSession
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * A YubiKey's HMAC-SHA1 challenge-response over NFC (a tap on the phone's back, while [activity] is in front) or USB
 * (YubiKit Android: `YubiKitManager` discovery, then `YubiOtpSession.calculateHmacSha1`). Read-only: nothing is ever
 * written to the key. The first key found answers; one exchange per [respond].
 */
class YubiKeyReader(private val context: Context, private val activity: () -> Activity?) {
    @Volatile private var pending: CompletableDeferred<ByteArray>? = null

    /**
     * Waits for a YubiKey and returns the 20-byte response of [slot] to [challenge], which must be the full 64-byte
     * padded challenge (docs/formats/COMPOSITE_KEY_V1.md §1.2). Throws [YubiKeyException]; [cancel] ends the wait.
     */
    suspend fun respond(slot: Int, challenge: ByteArray): ByteArray {
        require(challenge.size == CompositeKey.PADDED_CHALLENGE_SIZE) { "always the full 64-byte padded challenge" }
        val result = CompletableDeferred<ByteArray>()
        pending?.completeExceptionally(YubiKeyException(YubiKeyException.Code.CANCELLED, slot))
        pending = result
        val manager = YubiKitManager(context.applicationContext)
        val answered = AtomicBoolean(false)
        val onDevice: (YubiKeyDevice) -> Unit = { device ->
            // One exchange: a second key (or the same one again) during it is ignored.
            if (answered.compareAndSet(false, true)) {
                YubiOtpSession.create(device) { r ->
                    try {
                        result.complete(r.value.use { respondWith(it, slot, challenge) })
                    } catch (e: Throwable) {
                        result.completeExceptionally(failure(e, slot))
                    }
                }
            }
        }
        val host = activity()
        var usb = false
        var nfc = false
        withContext(Dispatchers.Main) {
            if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)) {
                manager.startUsbDiscovery(UsbConfiguration()) { onDevice(it) }
                usb = true
            }
            if (host != null) {
                nfc = try {
                    manager.startNfcDiscovery(NfcConfiguration(), host) { onDevice(it) }
                    true
                } catch (e: NfcNotAvailable) {
                    false
                }
            }
        }
        try {
            if (!usb && !nfc) throw YubiKeyException(YubiKeyException.Code.NO_TRANSPORT, slot)
            return result.await()
        } finally {
            if (pending === result) pending = null
            withContext(NonCancellable + Dispatchers.Main) {
                if (usb) manager.stopUsbDiscovery()
                if (nfc && host != null) manager.stopNfcDiscovery(host)
            }
        }
    }

    /** Ends a running [respond] with [YubiKeyException.Code.CANCELLED]. */
    fun cancel() {
        pending?.completeExceptionally(YubiKeyException(YubiKeyException.Code.CANCELLED))
    }

    companion object {
        /**
         * The exchange itself, on an open session. `calculateHmacSha1` copies the challenge into a 64-byte buffer it
         * first fills with its own pad byte (0x00, or 0x01 after a final 0x00): handed all 64 bytes, none of that pad
         * is left, so the key receives exactly our KeePassXC padding (`YubiKeyReaderTest` checks the wire bytes).
         */
        fun respondWith(session: YubiOtpSession, slot: Int, challenge: ByteArray): ByteArray {
            require(challenge.size == CompositeKey.PADDED_CHALLENGE_SIZE) { "always the full 64-byte padded challenge" }
            val response = session.calculateHmacSha1(if (slot == 1) Slot.ONE else Slot.TWO, challenge, null)
            if (response.size != CompositeKey.YUBIKEY_RESPONSE_SIZE) throw YubiKeyException(YubiKeyException.Code.BAD_ANSWER, slot)
            return response
        }

        /**
         * What a YubiKit failure means here. A lost NFC tag or an unplugged key is an [IOException] (`TagLostException`,
         * a broken USB transfer or CRC): "Touch your YubiKey again", never a crash and never a counted try.
         */
        fun failure(e: Throwable, slot: Int): YubiKeyException = when (e) {
            is YubiKeyException -> e
            is TimeoutException -> YubiKeyException(YubiKeyException.Code.TIMEOUT, slot)
            // No answer from the slot (OTP "no data", or an empty CCID response): not set up for challenge-response.
            is CommandRejectedException, is BadResponseException -> YubiKeyException(YubiKeyException.Code.SLOT_NOT_CONFIGURED, slot)
            is IOException -> YubiKeyException(YubiKeyException.Code.REMOVED, slot)
            else -> YubiKeyException(YubiKeyException.Code.BAD_ANSWER, slot)
        }
    }
}
