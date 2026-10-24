package app.localgatekeys.core.passkey

import java.io.ByteArrayOutputStream

/**
 * The CBOR subset WebAuthn needs (desktop `passkeys.cbor_encode`): ints, byte and text strings, maps whose
 * keys keep the given order. Port of Swift `CBOR`.
 */
sealed interface Cbor {
    data class Integer(val v: Long) : Cbor

    class Bytes(val v: ByteArray) : Cbor

    data class Text(val v: String) : Cbor

    /** A map; pairs are written in the order given. */
    data class Mapping(val pairs: List<Pair<Cbor, Cbor>>) : Cbor

    fun encoded(): ByteArray {
        val out = ByteArrayOutputStream()
        append(this, out)
        return out.toByteArray()
    }

    private companion object {
        fun head(major: Int, value: Long, out: ByteArrayOutputStream) {
            val m = major shl 5
            fun be(n: Int) {
                for (i in n - 1 downTo 0) out.write(((value ushr (8 * i)) and 0xFF).toInt())
            }
            when {
                value < 24 -> out.write(m or value.toInt())
                value <= 0xFF -> { out.write(m or 24); be(1) }
                value <= 0xFFFF -> { out.write(m or 25); be(2) }
                value <= 0xFFFF_FFFFL -> { out.write(m or 26); be(4) }
                else -> { out.write(m or 27); be(8) }
            }
        }

        fun append(c: Cbor, out: ByteArrayOutputStream) {
            when (c) {
                is Integer -> if (c.v >= 0) head(0, c.v, out) else head(1, -1 - c.v, out)
                is Bytes -> { head(2, c.v.size.toLong(), out); out.write(c.v) }
                is Text -> { val u = c.v.toByteArray(Charsets.UTF_8); head(3, u.size.toLong(), out); out.write(u) }
                is Mapping -> {
                    head(5, c.pairs.size.toLong(), out)
                    for ((k, v) in c.pairs) { append(k, out); append(v, out) }
                }
            }
        }
    }
}
