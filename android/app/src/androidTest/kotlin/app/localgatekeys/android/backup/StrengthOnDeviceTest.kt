package app.localgatekeys.android.backup

import app.localgatekeys.android.i18n.appTxt
import androidx.test.platform.app.InstrumentationRegistry
import app.localgatekeys.android.generator.PassphraseWordlist
import app.localgatekeys.core.password.StrengthEstimator
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The desktop password strength vectors on the device (Ruling 26): Android's character data is ICU's, not the JDK's,
 * and the backup gate uses the app's own dictionary (the packaged asset plus the built-in list).
 */
class StrengthOnDeviceTest {
    @Test fun every_desktop_vector_matches_with_the_apps_dictionary() {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        val doc = JSONObject(ctx.assets.open("vectors/password_strength/vectors.json").bufferedReader(Charsets.UTF_8).use { it.readText() })
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val packaged = PassphraseWordlist.parse(app.assets.open(PassphraseWordlist.ASSET).bufferedReader(Charsets.UTF_8).use { it.readText() })
        assertEquals(doc.getJSONObject("dictionary").getInt("wordlist_count"), packaged.size)
        val estimator = StrengthEstimator(packaged.toSet() + PassphraseWordlist.FALLBACK, packaged.size)
        val vectors = doc.getJSONArray("vectors")
        val wrong = ArrayList<String>()
        for (k in 0 until vectors.length()) {
            val v = vectors.getJSONObject(k)
            val password = v.getString("password")
            val e = estimator.estimate(password)
            if (e.score != v.getInt("score") || Math.abs(e.guessesLog10 - v.getDouble("guesses_log10")) > 1e-4) {
                wrong += "#$k: score ${e.score} vs ${v.getInt("score")}"
            }
        }
        assertTrue(wrong.joinToString("\n"), wrong.isEmpty())
        // The gate itself, as the export screen calls it.
        assertEquals(1, BackupPasswordCheck.check("Password123!", "Password123!", EnglishLikeTxt).score)
        assertTrue(BackupPasswordCheck.check("qwxzvbnmlkjh", "qwxzvbnmlkjh", EnglishLikeTxt).ok)
    }
}

private val EnglishLikeTxt: app.localgatekeys.android.i18n.Txt
    get() = appTxt()
