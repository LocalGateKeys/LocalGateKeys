package app.localgatekeys.android.crypto

import app.localgatekeys.core.crypto.Argon2id
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import com.lambdapioneer.argon2kt.Argon2Version

/** Native Argon2id (reference C implementation through argon2kt) for the phone; same results as the core Bouncy Castle one. */
class Argon2KtAdapter : Argon2id {
    private val argon2 by lazy { Argon2Kt() }

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
        return argon2.hash(
            mode = Argon2Mode.ARGON2_ID,
            password = password,
            salt = salt,
            tCostInIterations = iterations,
            mCostInKibibyte = memoryKiB,
            parallelism = parallelism,
            hashLengthInBytes = length,
            version = Argon2Version.V13,
        ).rawHashAsByteArray()
    }
}
