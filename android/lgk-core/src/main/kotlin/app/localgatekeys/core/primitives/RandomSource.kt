package app.localgatekeys.core.primitives

import java.security.SecureRandom

/** The only way production code obtains random bytes; tests inject fixed streams. */
interface RandomSource {
    fun bytes(count: Int): ByteArray
}

/** Cryptographically secure system randomness. */
class SystemRandomSource : RandomSource {
    private val rng = SecureRandom()

    override fun bytes(count: Int): ByteArray = ByteArray(count).also { rng.nextBytes(it) }
}

/** The only way production code reads the time (Unix seconds); tests inject fixed clocks. */
interface UnixClock {
    val now: Long
}

class SystemClock : UnixClock {
    override val now: Long get() = System.currentTimeMillis() / 1000L
}
