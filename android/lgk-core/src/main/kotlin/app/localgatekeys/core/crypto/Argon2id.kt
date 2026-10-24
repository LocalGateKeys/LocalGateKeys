package app.localgatekeys.core.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

interface Argon2id {
    /** Raw Argon2id (version 0x13) output. The password is used exactly as given. */
    fun derive(password: ByteArray, salt: ByteArray, memoryKiB: Int, iterations: Int, parallelism: Int, length: Int): ByteArray
}

class BouncyCastleArgon2id : Argon2id {
    override fun derive(
        password: ByteArray,
        salt: ByteArray,
        memoryKiB: Int,
        iterations: Int,
        parallelism: Int,
        length: Int,
    ): ByteArray {
        require(length > 0 && salt.size >= 8 && parallelism > 0 && iterations > 0 && memoryKiB >= 8 * parallelism) {
            "invalid Argon2 parameters"
        }
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(iterations)
            .withMemoryAsKB(memoryKiB)
            .withParallelism(parallelism)
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(length)
        gen.generateBytes(password, out)
        return out
    }
}

/** Holder for the Argon2id implementation; Part B swaps in a native one on Android. */
object Argon2 {
    @Volatile
    var default: Argon2id = BouncyCastleArgon2id()
}
