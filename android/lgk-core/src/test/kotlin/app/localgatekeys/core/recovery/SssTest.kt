package app.localgatekeys.core.recovery

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.FixedRandom
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Shamir over GF(256) against the shared vectors in tests/vectors/sss (port of tests/test_sss.py). */
class SssTest {
    private fun file(name: String) = File(Vectors.root, "sss/$name").also { check(it.isFile) { "vector missing: $it" } }
    private val hashicorp = Vectors.json(file("hashicorp.json")).obj().fields
    private val v1 = Vectors.json(file("v1.json")).obj().fields

    private fun JsonValue.i(k: String) = obj().fields.getValue(k).long().toInt()

    /** The slow, obviously right multiply: bit by bit with branches (test only). */
    private fun reference(a0: Int, b0: Int): Int {
        var a = a0
        var b = b0
        var p = 0
        repeat(8) {
            if (b and 1 != 0) p = p xor a
            val hi = a and 0x80
            a = (a shl 1) and 0xFF
            if (hi != 0) a = a xor 0x1B
            b = b shr 1
        }
        return p
    }

    @Test fun hashicorp_field_vectors() {
        for (c in hashicorp.getValue("add").arr()) assertEquals(c.i("out"), c.i("a") xor c.i("b"))
        val mult = hashicorp.getValue("mult").arr()
        assertEquals(4, mult.size)
        for (c in mult) assertEquals(c.i("out"), Sss.mul(c.i("a"), c.i("b")), "mult ${c.i("a")} ${c.i("b")}")
        for (c in hashicorp.getValue("div").arr()) assertEquals(c.i("out"), Sss.div(c.i("a"), c.i("b")))
        for (c in hashicorp.getValue("polynomial_eval").arr()) {
            val coeffs = IntArray(c.i("degree") + 1) { if (it == 0) c.i("intercept") else 0x5A }
            assertEquals(c.i("out"), Sss.evaluate(coeffs, c.i("x")))
        }
        assertEquals(0xc1, Sss.mul(0x57, 0x83)) // FIPS-197 4.2
    }

    @Test fun masked_multiply_matches_the_reference_for_every_pair() {
        for (a in 0..255) for (b in 0..255) assertEquals(reference(a, b), Sss.mul(a, b), "$a*$b")
    }

    @Test fun divide_inverts_multiply() {
        for (a in 0..255) for (b in 1..255) assertEquals(a, Sss.div(Sss.mul(a, b), b))
        assertFailsWith<ArithmeticException> { Sss.div(3, 0) }
    }

    @Test fun v1_vectors_split_byte_for_byte_and_combine_every_listed_subset() {
        val cases = v1.getValue("cases").arr()
        assertEquals(6, cases.size)
        for (c in cases) {
            val f = c.obj().fields
            val name = f.getValue("name").str()
            val coefficients = Vectors.hex(f.getValue("coefficients").str())
            var asked = -1
            val rng = object : RandomSource {
                override fun bytes(count: Int): ByteArray {
                    asked = count
                    return coefficients.copyOf()
                }
            }
            val secret = Vectors.hex(f.getValue("secret").str())
            val shares = Sss.split(secret, c.i("k"), c.i("n"), rng)
            assertEquals(coefficients.size, asked, name)
            val expected = f.getValue("shares").arr().map { Vectors.hex(it.str()) }
            assertEquals(expected.size, shares.size)
            expected.zip(shares).forEach { (e, s) -> assertContentEquals(e, s, name) }
            for (subset in f.getValue("combine_subsets").arr()) {
                val picked = subset.arr().map { expected[it.long().toInt() - 1] }
                assertContentEquals(secret, Sss.combine(picked), name)
                assertContentEquals(secret, Sss.combine(picked.reversed()), name)
            }
        }
    }

    @Test fun every_k_subset_combines_and_fresh_shares_differ() {
        val random = SystemRandomSource()
        val secret = random.bytes(32)
        for (n in 2..5) for (k in 2..n) {
            val shares = Sss.split(secret, k, n, random)
            subsets(n, k).forEach { s -> assertContentEquals(secret, Sss.combine(s.map { shares[it] })) }
        }
        val a = Sss.split(secret, 2, 3, random)
        val b = Sss.split(secret, 2, 3, random)
        assertFalse(a[0].contentEquals(b[0]))
    }

    @Test fun one_share_below_k_is_uniform_exactly() {
        // k = 2: for every x and secret byte, the 256 coefficients map onto all 256 share values.
        for (x in 1..5) for (s in 0..255) {
            val seen = BooleanArray(256)
            for (c in 0..255) seen[Sss.evaluate(intArrayOf(s, c), x)] = true
            assertTrue(seen.all { it }, "x=$x s=$s")
        }
    }

    @Test fun k_minus_one_shares_reconstruct_unrelated_bytes() {
        val random = SystemRandomSource()
        val secret = ByteArray(32)
        var matches = 0
        repeat(1000) {
            val shares = Sss.split(secret, 3, 5, random)
            val out = Sss.combine(shares.take(2))
            matches += out.count { it.toInt() == 0 }
        }
        // 1000 * 32 bytes, 1/256 expected to match: about 125 (sd about 11); six sd either side.
        assertTrue(matches in 60..190, "matches $matches")
    }

    @Test fun refusals() {
        val r = FixedRandom(ByteArray(256) { 7 })
        val secret = ByteArray(32) { 1 }
        for ((k, n) in listOf(1 to 2, 3 to 2, 2 to 6, 0 to 0, 6 to 6)) assertFailsWith<SssException> { Sss.split(secret, k, n, r) }
        assertFailsWith<SssException> { Sss.split(ByteArray(31), 2, 2, r) }
        assertFailsWith<SssException> { Sss.split(ByteArray(33), 2, 2, r) }
        assertFailsWith<SssException> { Sss.split(secret, 3, 3, FixedRandom(ByteArray(10))) }
        val shares = Sss.split(secret, 2, 3, SystemRandomSource())
        assertFailsWith<SssException> { Sss.combine(emptyList()) }
        assertFailsWith<SssException> { Sss.combine(shares.take(1)) }
        assertFailsWith<SssException> { Sss.combine(List(6) { shares[0] }) }
        assertFailsWith<SssException> { Sss.combine(listOf(shares[0], shares[0])) }
        assertFailsWith<SssException> { Sss.combine(listOf(shares[0], shares[1].copyOf().also { it[0] = 1; it[1] = 9 })) }
        assertFailsWith<SssException> { Sss.combine(listOf(shares[0], shares[1].copyOf(32))) }
        assertFailsWith<SssException> { Sss.combine(listOf(shares[0], shares[1].copyOf().also { it[0] = 0 })) }
    }

    private fun subsets(n: Int, k: Int): List<List<Int>> {
        if (k == 0) return listOf(emptyList())
        if (n < k) return emptyList()
        return subsets(n - 1, k) + subsets(n - 1, k - 1).map { it + (n - 1) }
    }
}
