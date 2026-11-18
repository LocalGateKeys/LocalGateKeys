package app.localgatekeys.android.security

import app.localgatekeys.android.autofill.testRules
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.UrlMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The shared `tests/vectors/health/site_cases.json` (Windows, iPhone and Android must give the same ids). */
class VaultHealthSiteCasesTest {
    private fun cases(): List<Map<String, JsonValue>> {
        val repo = System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot not set")
        val file = File(repo, "tests/vectors/health/site_cases.json")
        check(file.isFile) { "vector missing: $file" }
        return (CanonicalJson.parse(file.readBytes()) as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }
    }

    private fun strings(v: JsonValue?): List<String> = (v as JsonValue.Arr).items.map { (it as JsonValue.Str).v }

    private fun features(case: Map<String, JsonValue>): SiteFeatures {
        val sites = (case["sites"] as JsonValue.Obj).fields.mapValues { strings(it.value).toSet() }
        return SiteFeatures(sites, UrlMatcher(testRules))
    }

    private fun run(case: Map<String, JsonValue>, withFeatures: Boolean = true): VaultHealth {
        val logins = (case["logins"] as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }.map { l ->
            HealthLogin(
                id = (l["id"] as JsonValue.Str).v, title = "", password = "Xk9#mQ2\$vLp7!zRt",
                hasTotp = (l["has_totp"] as JsonValue.Bool).v, updatedAt = null, urls = strings(l["urls"]),
            )
        }
        val cache = StrengthCache { 4 }
        return if (withFeatures) {
            VaultHealth.compute(logins, emptySet(), 0L, cache, features(case), strings(case["passkey_domains"]).toSet())
        } else {
            VaultHealth.compute(logins, emptySet(), 0L, cache)
        }
    }

    @Test fun every_case_gives_the_expected_ids() {
        val all = cases()
        assertTrue("the vector file has cases", all.size >= 19)
        for (case in all) {
            val name = (case["name"] as JsonValue.Str).v
            val health = run(case)
            val expected = (case["expected"] as JsonValue.Obj).fields
            assertEquals(name + " http", strings(expected["http"]).toSet(), health.insecure)
            assertEquals(name + " no_2fa", strings(expected["no_2fa"]).toSet(), health.noTwoFactor)
            assertEquals(name + " passkey", strings(expected["passkey"]).toSet(), health.passkeyAvailable)
        }
    }

    @Test fun without_features_2fa_and_passkey_are_empty_but_http_still_works() {
        val case = cases().first { (it["name"] as JsonValue.Str).v == "mixed_logins" }
        val health = run(case, withFeatures = false)
        assertEquals(emptySet<String>(), health.noTwoFactor)
        assertEquals(emptySet<String>(), health.passkeyAvailable)
        assertEquals(setOf("a"), health.insecure)
    }
}
