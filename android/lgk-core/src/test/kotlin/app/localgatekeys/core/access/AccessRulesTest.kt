package app.localgatekeys.core.access

import app.localgatekeys.core.access.AccessRules.DeviceClass
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.support.Vectors
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.Test
import app.localgatekeys.core.support.assertEq
import app.localgatekeys.core.support.assertTr

class AccessRulesTest {
    private fun s(v: String) = JsonValue.Str(v)

    @Test
    fun a_require_master_password_that_is_not_a_boolean_is_read_as_on() {
        // Unknown = strictest (scan A-L1): only an explicit false is off.
        for (v in listOf(s("yes"), JsonValue.Int(0), JsonValue.Null)) {
            val r = login() + ("policy" to JsonValue.Obj(mapOf("require_master_password" to v)))
            assertTrue(AccessRules.effective(r, DeviceClass.PHONE, "2026-01-01").reauth, v.toString())
            assertTrue(AccessRules.tightens(login(), r), v.toString())
        }
        assertFalse(AccessRules.effective(login(), DeviceClass.PHONE, "2026-01-01").reauth)
        assertFalse(AccessRules.strictPolicy(emptyMap()))
    }

    private fun login(access: JsonValue? = null, strict: Boolean = false, fill: String = "click"): Map<String, JsonValue> {
        val scope = linkedMapOf<String, JsonValue>("origin" to s("https://example.com"))
        if (access != null) scope["access"] = access
        return mapOf(
            "id" to s("a"), "kind" to s("web"), "label" to s("A"), "username" to s("u"), "password" to s("p"),
            "scope" to JsonValue.Obj(scope),
            "policy" to JsonValue.Obj(mapOf("fill" to s(fill), "require_master_password" to JsonValue.Bool(strict))),
        )
    }

    private fun access(vararg kv: Pair<String, String>) = JsonValue.Obj(kv.associate { it.first to s(it.second) })

    @Test
    fun noRulesAllowsEverything() {
        val e = AccessRules.effective(login(), DeviceClass.PHONE, "2026-11-15")
        assertEquals(AccessRules.NONE, e)
        assertFalse(e.anyRule)
    }

    @Test
    fun existingPolicyIsReadOnPhones() {
        val strict = AccessRules.effective(login(strict = true), DeviceClass.PHONE, "2026-11-15")
        assertTrue(strict.reauth)
        assertTrue(strict.autofill)
        val never = AccessRules.effective(login(fill = "never"), DeviceClass.PHONE, "2026-11-15")
        assertFalse(never.autofill)
        assertFalse(never.reauth)
        // An unknown fill value is never (the normaliser's rule).
        assertFalse(AccessRules.effective(login(fill = "sometimes"), DeviceClass.PHONE, "2026-11-15").autofill)
    }

    @Test
    fun eachKeyAlone() {
        val once = AccessRules.effective(login(access("copy" to "once")), DeviceClass.PHONE, "2026-11-15")
        assertTrue(once.copyOnce)
        assertTrue(once.autofill)
        assertTrue(AccessRules.effective(login(access("copy" to "twice")), DeviceClass.PHONE, "2026-11-15").copyOnce)
        val view = AccessRules.effective(login(access("phones" to "view")), DeviceClass.PHONE, "2026-11-15")
        assertTrue(view.phoneView)
        assertFalse(view.autofill)
        assertTrue(view.phoneRefuses(DeviceClass.PHONE))
        val onComputer = AccessRules.effective(login(access("phones" to "view")), DeviceClass.COMPUTER, "2026-11-15")
        assertTrue(onComputer.autofill)
        assertFalse(onComputer.phoneRefuses(DeviceClass.COMPUTER))
    }

    @Test
    fun expiryFromThatDayOn() {
        fun on(today: String) = AccessRules.effective(login(access("expires" to "2026-11-15")), DeviceClass.PHONE, today)
        assertFalse(on("2026-11-14").expired)
        assertTrue(on("2026-11-15").expired)
        assertTrue(on("2026-11-15").reauth)
        assertFalse(on("2026-11-15").autofill)
        assertTrue(on("2026-11-16").expired)
        assertEquals("2026-11-15", on("2026-11-14").expiresOn)
        // Malformed dates expire now; the compact and week forms are not the dash form.
        for (bad in listOf("2026-02-30", "20261115", "2026-W46", "x")) {
            assertTr(bad, AccessRules.effective(login(access("expires" to bad)), DeviceClass.PHONE, "2000-01-01").expired)
        }
        assertFalse(AccessRules.effective(login(access("expires" to "")), DeviceClass.PHONE, "2026-11-15").expired)
    }

    @Test
    fun unknownKeyOrShapeTurnsEverythingOn() {
        for (raw in listOf(access("biometric_only" to "yes"), s("x"), JsonValue.Arr(emptyList()))) {
            val e = AccessRules.effective(login(raw), DeviceClass.COMPUTER, "2026-11-15")
            assertTrue(e.reauth)
            assertFalse(e.autofill)
            assertTrue(e.copyOnce)
            assertTrue(e.phoneView)
            assertFalse(e.expired)
            assertTrue(e.unknownRule)
        }
    }

    @Test
    fun writeFormKeepsOnlyNonDefaults() {
        assertNull(AccessRules.Settings().write())
        assertEquals(access("copy" to "once"), AccessRules.Settings(copyOnce = true).write())
        assertEquals(access("phones" to "view", "expires" to "2027-03-31"), AccessRules.Settings(phonesView = true, expires = "2027-03-31").write())
        val back = AccessRules.Settings.of(access("copy" to "once", "expires" to "2027-01-01"))
        assertEquals(AccessRules.Settings(copyOnce = true, expires = "2027-01-01"), back)
        val removed = AccessRules.withAccess(login(access("copy" to "once")), null)
        assertNull(AccessRules.accessOf(removed))
        assertEquals(s("https://example.com"), (removed["scope"] as JsonValue.Obj).fields["origin"])
    }

    @Test
    fun tighteningNeedsProLooseningDoesNot() {
        val plain = login()
        assertTrue(AccessRules.tightens(plain, login(access("copy" to "once"))))
        assertTrue(AccessRules.tightens(plain, login(strict = true)))
        assertTrue(AccessRules.tightens(plain, login(fill = "never")))
        assertTrue(AccessRules.tightens(login(access("expires" to "2027-01-01")), login(access("expires" to "2026-12-01"))))
        assertFalse(AccessRules.tightens(login(access("copy" to "once")), plain))
        assertFalse(AccessRules.tightens(login(strict = true), plain))
        assertFalse(AccessRules.tightens(login(access("expires" to "2026-12-01")), login(access("expires" to "2027-01-01"))))
    }

    @Test
    fun stricterPerKey() {
        val a = access("copy" to "once", "expires" to "2027-05-01")
        val b = JsonValue.Obj(mapOf("phones" to s("view"), "expires" to s("2027-03-31"), "future" to s("ü")))
        assertEquals(
            JsonValue.Obj(mapOf("copy" to s("once"), "phones" to s("view"), "expires" to s("2027-03-31"), "future" to s("ü"))),
            AccessRules.stricter(a, b),
        )
        assertEquals(a, AccessRules.stricter(a, null))
        assertEquals(s("x"), AccessRules.stricter(a, s("x")))
        assertEquals(access("expires" to "bad"), AccessRules.stricter(access("expires" to "2027-01-01"), access("expires" to "bad")))
        val p = AccessRules.stricterPolicy(
            JsonValue.Obj(mapOf("fill" to s("click"), "require_master_password" to JsonValue.Bool(false), "sign_in" to s("inherit"))),
            JsonValue.Obj(mapOf("fill" to s("never"), "require_master_password" to JsonValue.Bool(true))),
        )
        assertEquals(JsonValue.Obj(mapOf("fill" to s("never"), "require_master_password" to JsonValue.Bool(true), "sign_in" to s("inherit"))), p)
    }

    @Test
    fun normaliserKeepsAccessByteForByte() {
        val raw = JsonValue.Obj(mapOf("copy" to s("once"), "später" to s("日本"), "expires" to s("2027-03-31")))
        val out = Normalise.normalForm(Namespace.ENTRY, JsonValue.Obj(login(raw))) as JsonValue.Obj
        val kept = (out.fields["scope"] as JsonValue.Obj).fields["access"]!!
        assertTrue(CanonicalJson.encode(raw, Dialect.UTF8).contentEquals(CanonicalJson.encode(kept, Dialect.UTF8)))
    }

    // MARK: shared vectors (tests/vectors/access/)

    private fun cases(file: String): List<Map<String, JsonValue>> {
        val root = Vectors.json(Vectors.optional("access/$file"))
        val list = (root as? JsonValue.Arr)?.items ?: ((root as JsonValue.Obj).fields["cases"] as JsonValue.Arr).items
        return list.map { (it as JsonValue.Obj).fields }
    }

    @Test
    fun effectiveVectors() {
        for (c in cases("effective.json")) {
            val e = AccessRules.effective(
                (c.getValue("record") as JsonValue.Obj).fields, DeviceClass.of((c.getValue("device_class") as JsonValue.Str).v),
                (c.getValue("today") as JsonValue.Str).v,
            )
            val want = (c.getValue("expected") as JsonValue.Obj).fields
            val got = mapOf(
                "reauth" to e.reauth, "autofill" to e.autofill, "copy_once" to e.copyOnce, "phone_view" to e.phoneView, "expired" to e.expired,
            )
            for ((k, v) in got) want[k]?.let { assertEq("${c["name"]} $k", it, JsonValue.Bool(v)) }
        }
    }

    @Test
    fun preserveVectors() {
        for (c in cases("preserve.json")) {
            val out = Normalise.normalForm(Namespace.ENTRY, c.getValue("input_entry"))
            val want = c.getValue("expected_normal_form")
            assertTr("${c["name"]}", CanonicalJson.encode(want, Dialect.UTF8).contentEquals(CanonicalJson.encode(out, Dialect.UTF8)))
        }
    }

    @Test
    fun stricterVectors() {
        for (c in cases("stricter.json")) {
            val want = c["expected"]?.takeIf { it != JsonValue.Null }
            assertEq("${c["name"]}", want, AccessRules.stricter(c["a"]?.takeIf { it != JsonValue.Null }, c["b"]?.takeIf { it != JsonValue.Null }))
        }
    }
}
