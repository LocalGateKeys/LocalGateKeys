package app.localgatekeys.core.json

import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CanonicalJsonTest {
    private fun vectors(): JsonValue.Obj = Vectors.json(Vectors.sync("canonical_json.json")).obj()

    private fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)

    private fun roundTrip(key: String, dialect: Dialect) {
        val rows = vectors().fields.getValue(key).arr()
        assertFalse(rows.isEmpty())
        for (row in rows) {
            val r = row.obj().fields
            val text = r.getValue("value_json").str()
            val out = CanonicalJson.encode(CanonicalJson.parse(utf8(text)), dialect)
            assertEquals(r.getValue("canonical_hex").str(), Vectors.hexString(out), text)
        }
    }

    private fun assertKind(kind: JsonException.Kind, bytes: ByteArray, label: String) {
        val e = assertFailsWith<JsonException>(label) { CanonicalJson.parse(bytes) }
        assertEquals(kind, e.kind, label)
    }

    @Test fun utf8_vectors() = roundTrip("utf8", Dialect.UTF8)

    @Test fun ascii_vectors() = roundTrip("ascii", Dialect.ASCII)

    @Test fun rejected_vectors() {
        val rows = vectors().fields.getValue("rejected").arr()
        val expected = mapOf(
            """{"n":9223372036854775808}""" to JsonException.Kind.INT_OUT_OF_RANGE,
            """{"x":NaN}""" to JsonException.Kind.NON_FINITE,
            """{"x":Infinity}""" to JsonException.Kind.NON_FINITE,
            """{"a":1,"a":2}""" to JsonException.Kind.DUPLICATE_KEY,
            """{"s":"\ud800"}""" to JsonException.Kind.LONE_SURROGATE,
        )
        assertEquals(expected.size, rows.size)
        for (row in rows) {
            val text = row.obj().fields.getValue("text").str()
            assertKind(expected.getValue(text), utf8(text), text)
        }
    }

    @Test fun more_rejections() {
        val cases = listOf(
            "-Infinity" to JsonException.Kind.NON_FINITE,
            "1e999" to JsonException.Kind.NON_FINITE,
            "-9223372036854775808" to JsonException.Kind.INT_OUT_OF_RANGE,
            """"\udc00"""" to JsonException.Kind.LONE_SURROGATE,
            """"\ud83dx"""" to JsonException.Kind.LONE_SURROGATE,
            """"\ud800\u0041"""" to JsonException.Kind.LONE_SURROGATE,
            "01" to JsonException.Kind.SYNTAX,
            "[1,]" to JsonException.Kind.SYNTAX,
            "{} x" to JsonException.Kind.SYNTAX,
            "\"a" to JsonException.Kind.SYNTAX,
        )
        for ((t, k) in cases) assertKind(k, utf8(t), t)
        // Overlong NUL, raw surrogate (ED A0 80) and a truncated sequence are all invalid UTF-8.
        assertKind(JsonException.Kind.SYNTAX, byteArrayOf(0x22, 0xC0.toByte(), 0x80.toByte(), 0x22), "overlong")
        assertKind(JsonException.Kind.SYNTAX, byteArrayOf(0x22, 0xED.toByte(), 0xA0.toByte(), 0x80.toByte(), 0x22), "surrogate")
        assertKind(JsonException.Kind.SYNTAX, byteArrayOf(0x22, 0xE2.toByte(), 0x82.toByte(), 0x22), "truncated")
        val e = assertFailsWith<JsonException> { CanonicalJson.encode(JsonValue.Float(Double.NaN), Dialect.UTF8) }
        assertEquals(JsonException.Kind.NON_FINITE, e.kind)
    }

    @Test fun depth_limit_is_512() {
        fun nested(n: Int) = utf8("[".repeat(n) + "]".repeat(n))
        CanonicalJson.parse(nested(512))
        assertKind(JsonException.Kind.SYNTAX, nested(513), "depth 513")
    }

    @Test fun int_bounds() {
        assertEquals(JsonValue.Int(Long.MAX_VALUE), CanonicalJson.parse(utf8("9223372036854775807")))
        assertEquals(JsonValue.Int(-Long.MAX_VALUE), CanonicalJson.parse(utf8("-9223372036854775807")))
    }

    @Test fun sorts_keys_by_code_point_not_utf16() {
        val v = JsonValue.Obj(mapOf("\uFFFF" to JsonValue.Int(1), "\uD83D\uDE00" to JsonValue.Int(2)))
        val s = String(CanonicalJson.encode(v, Dialect.UTF8), Charsets.UTF_8)
        assertEquals("{\"\uFFFF\":1,\"\uD83D\uDE00\":2}", s)
        val w = JsonValue.Obj(
            mapOf("\uD83D\uDD11" to JsonValue.Int(4), "\uFF5A" to JsonValue.Int(3), "\u00E9" to JsonValue.Int(2), "a" to JsonValue.Int(1)),
        )
        assertEquals(
            "{\"a\":1,\"\u00E9\":2,\"\uFF5A\":3,\"\uD83D\uDD11\":4}",
            String(CanonicalJson.encode(w, Dialect.UTF8), Charsets.UTF_8),
        )
    }

    @Test fun python_float_repr_edge_cases() {
        val cases = listOf(
            0.1 to "0.1", 1e-07 to "1e-07", 1e15 to "1000000000000000.0", 1e16 to "1e+16",
            100.0 to "100.0", -0.0 to "-0.0", 0.0 to "0.0", 1.5e+300 to "1.5e+300", 1.5 to "1.5",
            0.0001 to "0.0001", 0.00001 to "1e-05", 123456789012345.6 to "123456789012345.6",
            1.2345e20 to "1.2345e+20", -2.5e-10 to "-2.5e-10", 5e-324 to "5e-324", 1.5e-7 to "1.5e-07",
            1.7976931348623157e308 to "1.7976931348623157e+308", 5.0E-5 to "5e-05",
            Math.scalb(1.0, -44) to "5.684341886080802e-14", 1e23 to "1e+23", 9007199254740993.0 to "9007199254740992.0",
        )
        for ((d, s) in cases) assertEquals(s, PythonFloat.repr(d))
    }

    @Test fun int_float_distinction_survives() {
        val t = "[100.0,100,1e+16,-0.0,4611686018427387904]"
        val out = CanonicalJson.encode(CanonicalJson.parse(utf8(t)), Dialect.UTF8)
        assertEquals(t, String(out, Charsets.UTF_8))
        assertTrue(CanonicalJson.parse(utf8("1")) is JsonValue.Int)
        assertTrue(CanonicalJson.parse(utf8("1E2")) is JsonValue.Float)
    }

    @Test fun accessors_throw_on_wrong_kind() {
        assertFailsWith<IllegalArgumentException> { JsonValue.Null.obj() }
        assertFailsWith<IllegalArgumentException> { JsonValue.Int(1).str() }
        assertFailsWith<IllegalArgumentException> { JsonValue.Str("x").long() }
        assertFailsWith<IllegalArgumentException> { JsonValue.Str("x").arr() }
    }
}
