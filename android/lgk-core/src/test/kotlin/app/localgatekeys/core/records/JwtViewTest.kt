package app.localgatekeys.core.records

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The shared JWT vectors (tests/vectors/jwt/cases.json, copied to test resources). Mirror of Swift `JWTViewTests`. */
class JwtViewTest {
    private val cases: List<JsonValue> = CanonicalJson.parse(
        javaClass.getResourceAsStream("/jwt_cases.json")!!.use { it.readBytes() },
    ).arr()

    private fun long(v: JsonValue?): Long? = (v as? JsonValue.Int)?.v

    @Test fun vectors() {
        assertTrue(cases.size >= 42)
        for (c in cases) {
            val f = c.obj().fields
            val name = f.getValue("name").str()
            val info = JwtView.decode(f.getValue("value").str())
            val expected = f.getValue("result")
            if (expected is JsonValue.Null) {
                assertNull(info, "vector $name")
                continue
            }
            val e = expected.obj().fields
            assertNotNull(info, "vector $name")
            assertEquals(e.getValue("header"), info.header, "header $name")
            assertEquals(e.getValue("claims"), info.claims, "claims $name")
            assertEquals((e.getValue("alg") as? JsonValue.Str)?.v, info.alg, "alg $name")
            assertEquals(long(e["issued"]), info.issued, "issued $name")
            assertEquals(long(e["not_before"]), info.notBefore, "not_before $name")
            assertEquals(long(e["expires"]), info.expires, "expires $name")
            val now = long(f["now"])
            if (now != null) assertEquals((f.getValue("expired") as JsonValue.Bool).v, info.expired(now), "expired $name")
        }
    }

    @Test fun oversizedValueIsNotDecoded() {
        val good = cases.first { it.obj().fields.getValue("name").str() == "hs256_basic" }.obj().fields.getValue("value").str()
        assertNotNull(JwtView.decode(good))
        assertNull(JwtView.decode(good + "A".repeat(JwtView.MAX_CHARS)))
    }

    @Test fun expiredBoundary() {
        val good = cases.first { it.obj().fields.getValue("name").str() == "hs256_basic" }.obj().fields.getValue("value").str()
        val info = JwtView.decode(good)!!
        assertTrue(info.expired(1_800_000_000))
        assertFalse(info.expired(1_799_999_999))
    }
}
