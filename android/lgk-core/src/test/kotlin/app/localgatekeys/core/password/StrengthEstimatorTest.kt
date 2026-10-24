package app.localgatekeys.core.password

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The desktop's `estimate_strength`, pinned by tests/vectors/password_strength/vectors.json (desktop-generated). */
class StrengthEstimatorTest {
    private val doc = (Vectors.json(File(Vectors.root, "password_strength/vectors.json")) as JsonValue.Obj).fields

    /** Desktop `load_wordlist()` over the packaged list, plus the built-in list's words not in it (`_word_set()`). */
    private val estimator: StrengthEstimator = run {
        val dict = (doc.getValue("dictionary") as JsonValue.Obj).fields
        val asset = File(Vectors.root.parentFile.parentFile, "src/localvault/assets/eff_large_wordlist.txt")
        val packaged = asset.readText(Charsets.UTF_8).lines().map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && Regex("[a-z]{3,12}").matches(it) }.toSortedSet()
        assertEquals((dict.getValue("wordlist_count") as JsonValue.Int).v.toInt(), packaged.size)
        val extra = (dict.getValue("extra_words") as JsonValue.Arr).items.map { (it as JsonValue.Str).v }
        StrengthEstimator(packaged + extra, packaged.size)
    }

    @Test fun every_desktop_vector_matches() {
        val vectors = (doc.getValue("vectors") as JsonValue.Arr).items.map { (it as JsonValue.Obj).fields }
        assertTrue(vectors.size >= 300)
        val wrong = ArrayList<String>()
        for (v in vectors) {
            val password = (v.getValue("password") as JsonValue.Str).v
            val score = (v.getValue("score") as JsonValue.Int).v.toInt()
            val log10 = when (val g = v.getValue("guesses_log10")) {
                is JsonValue.Float -> g.v
                is JsonValue.Int -> g.v.toDouble()
                else -> error("bad vector")
            }
            val e = estimator.estimate(password)
            if (e.score != score || Math.abs(e.guessesLog10 - log10) > 1e-4) {
                wrong += "${password.take(40)}: score ${e.score} vs $score, log10 ${e.guessesLog10} vs $log10"
            }
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} mismatches:\n" + wrong.joinToString("\n"))
    }

    @Test fun the_reviews_examples() {
        for (weak in listOf("Password123!", "P@ssw0rd2026", "Qwerty123456!")) assertEquals(1, estimator.estimate(weak).score, weak)
        assertEquals(4, estimator.estimate("qwxzvbnmlkjh").score)
        assertEquals(0, estimator.estimate("").score)
        assertEquals("Strong", StrengthEstimator.LABELS[3])
    }

    @Test fun nothing_prints_the_password() {
        val e = estimator.estimate("hunter2hunter2")
        assertTrue(!e.toString().contains("hunter"))
        assertTrue(e.matches.none { it.toString().contains("hunter") })
    }
}
