package app.localgatekeys.core.recovery

import app.localgatekeys.core.primitives.RandomSource

/** Bad parameters or malformed shares (desktop `sss.SSSError`). */
class SssException(message: String) : IllegalArgumentException(message)

/**
 * Shamir's secret sharing over GF(2^8) for emergency-access shards: port of `src/localvault/sss.py` (vectors:
 * `tests/vectors/sss`). The field uses the AES polynomial 0x11b; the secret is exactly 32 bytes; share `x` (1..n) is
 * `[x] + 32 bytes`; one `rng.bytes(32 * (k - 1))` call gives `coeffs[j * (k - 1) + (d - 1)]`, the degree-`d`
 * coefficient for secret byte `j`. [combine] cannot tell a wrong share or too few shares: integrity comes from the
 * signed `.lgkheir` envelope and the plan's entropy check.
 *
 * Side channels (best effort on the JVM): the log/exp tables are only ever indexed by public share indices (the
 * Lagrange basis). Secret bytes never index a table and never choose a branch: they only go through [mul], a fixed
 * eight-round shift-and-xor multiply with masks. Working buffers are zeroed before return.
 */
object Sss {
    const val SECRET_LEN = 32
    const val SHARE_LEN = 1 + SECRET_LEN
    const val MIN_K = 2
    const val MAX_N = 5

    private val EXP = IntArray(510)
    private val LOG = IntArray(256)

    init {
        // 0x03 generates the multiplicative group of GF(2^8) mod 0x11b.
        var value = 1
        for (power in 0 until 255) {
            EXP[power] = value
            LOG[value] = power
            val reduce = if ((value and 0x80) != 0) 0x1B else 0 // public table build, not secret data
            value = value xor (((value shl 1) xor reduce) and 0xFF)
        }
        for (power in 255 until 510) EXP[power] = EXP[power - 255]
    }

    /** `a * b` in GF(2^8) mod 0x11b: no table lookups and no data-dependent branches. */
    internal fun mul(a0: Int, b0: Int): Int {
        var a = a0 and 0xFF
        var b = b0 and 0xFF
        var p = 0
        for (round in 0 until 8) {
            p = p xor (a and -(b and 1))
            a = ((a shl 1) xor (0x1B and -(a ushr 7))) and 0xFF
            b = b ushr 1
        }
        return p
    }

    /** `a / b` with the log/exp tables: only for public values (share indices). */
    internal fun div(a: Int, b: Int): Int {
        if (b == 0) throw ArithmeticException("division by zero in GF(256)")
        if (a == 0) return 0
        return EXP[LOG[a] + 255 - LOG[b]]
    }

    /** Horner evaluation of `coeffs[0] + coeffs[1] x + ...` at [x]. */
    internal fun evaluate(coeffs: IntArray, x: Int): Int {
        var y = 0
        for (i in coeffs.indices.reversed()) y = mul(y, x) xor coeffs[i]
        return y
    }

    /** Splits a 32-byte [secret] into [n] shares, any [k] of which recover it (2 <= k <= n <= 5). */
    fun split(secret: ByteArray, k: Int, n: Int, rng: RandomSource): List<ByteArray> {
        if (!(MIN_K <= k && k <= n && n <= MAX_N)) throw SssException("need $MIN_K <= k <= n <= $MAX_N")
        if (secret.size != SECRET_LEN) throw SssException("secret must be $SECRET_LEN bytes")
        val degree = k - 1
        val coeffs = rng.bytes(SECRET_LEN * degree)
        val poly = IntArray(k)
        val outs = List(n) { ByteArray(SHARE_LEN) }
        try {
            if (coeffs.size != SECRET_LEN * degree) throw SssException("rng returned the wrong number of bytes")
            for (j in 0 until SECRET_LEN) {
                poly[0] = secret[j].toInt() and 0xFF
                for (d in 1..degree) poly[d] = coeffs[j * degree + d - 1].toInt() and 0xFF
                for (i in 0 until n) outs[i][1 + j] = evaluate(poly, i + 1).toByte()
            }
            return outs.mapIndexed { i, out -> out.copyOf().also { it[0] = (i + 1).toByte() } }
        } finally {
            coeffs.fill(0)
            poly.fill(0)
            outs.forEach { it.fill(0) }
        }
    }

    /** Recovers the secret from 2..5 shares with distinct indices. Fewer than `k` shares give unrelated bytes. */
    fun combine(shares: List<ByteArray>): ByteArray {
        if (shares.size !in MIN_K..MAX_N) throw SssException("need $MIN_K to $MAX_N shares")
        if (shares.any { it.size != SHARE_LEN }) throw SssException("each share must be $SHARE_LEN bytes")
        val xs = shares.map { it[0].toInt() and 0xFF }
        if (0 in xs) throw SssException("share index 0 is not allowed")
        if (xs.toSet().size != xs.size) throw SssException("duplicate share index")
        // The Lagrange basis at x = 0 depends only on the public indices: L_i = prod(x_m) / prod(x_i - x_m), m != i.
        val basis = xs.mapIndexed { i, xi ->
            var num = 1
            var den = 1
            xs.forEachIndexed { m, xm ->
                if (m != i) {
                    num = mul(num, xm)
                    den = mul(den, xi xor xm)
                }
            }
            div(num, den)
        }
        val out = ByteArray(SECRET_LEN)
        for (j in 0 until SECRET_LEN) {
            var acc = 0
            for (i in shares.indices) acc = acc xor mul(shares[i][1 + j].toInt() and 0xFF, basis[i])
            out[j] = acc.toByte()
        }
        return out
    }
}
