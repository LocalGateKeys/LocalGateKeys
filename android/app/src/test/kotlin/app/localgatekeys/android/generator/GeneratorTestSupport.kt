package app.localgatekeys.android.generator

import app.localgatekeys.core.primitives.RandomSource
import java.io.File

/** The Swift test `CountingRandom(start:)`: bytes start, start+37, start+74, ... (wrapping), so every run repeats. */
class StepRandom(start: Int = 0) : RandomSource {
    private var next = start and 0xff
    override fun bytes(count: Int): ByteArray = ByteArray(count) {
        val b = next
        next = (next + 37) and 0xff
        b.toByte()
    }
}

/** The packaged list as the app ships it (`android/app/src/main/assets`), read from the repository in JVM tests. */
object TestWordlist {
    val repoRoot: File = File(checkNotNull(System.getProperty("lgk.repoRoot")) { "lgk.repoRoot not set" })
    val asset: File = File(repoRoot, "android/app/src/main/assets/${PassphraseWordlist.ASSET}")

    /** Makes [PassphraseWordlist.packaged] the shipped list, as LgkApp does on the phone. */
    fun install() = PassphraseWordlist.install { asset.readText(Charsets.UTF_8) }
}
