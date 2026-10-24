package app.localgatekeys.android.ui.sync

import app.localgatekeys.android.sync.SyncVectors
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The scanner's frame decoding: a QR code drawn into a camera-like luminance plane is read back exactly. */
class QrScannerDecodeTest {
    /** [text] as a QR code on a light frame of [width] x [height] with [rowStride] bytes per row (padding filled with junk). */
    private fun frame(text: String, width: Int, height: Int, rowStride: Int): ByteArray {
        val size = minOf(width, height) * 3 / 4
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size)
        val out = ByteArray(rowStride * height) { 0x55 }
        val left = (width - size) / 2
        val top = (height - size) / 2
        for (y in 0 until height) for (x in 0 until width) {
            val inside = x - left in 0 until size && y - top in 0 until size
            val dark = inside && matrix[x - left, y - top]
            out[y * rowStride + x] = if (dark) 16 else 235.toByte()
        }
        return out
    }

    @Test fun reads_the_pairing_code_from_a_frame() {
        val text = SyncVectors.qrText()
        assertEquals(text, QrScanner.decode(frame(text, 640, 480, 640), 640, 480, 640))
    }

    @Test fun honours_the_row_stride() {
        val text = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        assertEquals(text, QrScanner.decode(frame(text, 640, 480, 704), 640, 480, 704))
    }

    @Test fun a_frame_without_a_code_reads_nothing() {
        assertNull(QrScanner.decode(ByteArray(640 * 480) { 0x7F }, 640, 480))
        assertNull(QrScanner.decode(ByteArray(10), 640, 480)) // too short for its size
        assertNull(QrScanner.decode(ByteArray(0), 0, 0))
    }
}
