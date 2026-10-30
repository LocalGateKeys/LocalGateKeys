package app.localgatekeys.core.crypto

import app.localgatekeys.core.primitives.Casefold
import java.security.MessageDigest
import java.text.Normalizer

/**
 * A recovery phrase problem. [message] is English for logs and never contains the phrase; screens show their own text
 * for [reason].
 */
class RecoveryPhraseException(val reason: Reason, message: String) : Exception(message) {
    enum class Reason { WORD_LIST_MISSING, WORD_LIST_DAMAGED, BAD_ENTROPY, MALFORMED, WRONG_WORD_COUNT, UNKNOWN_WORD, CHECKSUM }
}

/**
 * The 24-word recovery phrase: BIP39 English over 256 bits of entropy plus an 8-bit checksum. A port of the desktop
 * `vault.py` `phrase_from_entropy` / `entropy_from_phrase` (and `ios/LGKCore/.../BIP39.swift`): same list and digest,
 * NFKD + casefold + whitespace split.
 */
object Bip39 {
    const val WORD_LIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    const val WORD_COUNT = 24
    private const val MAX_INPUT = 2048

    val words: List<String> by lazy { load() }
    private val lookup: Map<String, Int> by lazy { words.withIndex().associate { (i, w) -> w to i } }

    private fun load(): List<String> {
        val text = Bip39::class.java.getResourceAsStream("bip39_english.txt")?.use { it.readBytes().toString(Charsets.UTF_8) }
            ?: throw RecoveryPhraseException(RecoveryPhraseException.Reason.WORD_LIST_MISSING, "The recovery word list is missing from this installation")
        val list = text.split(Regex("\\s+")).filter { it.isNotEmpty() }
        val digest = MessageDigest.getInstance("SHA-256").digest((list.joinToString("\n") + "\n").toByteArray(Charsets.UTF_8))
        val hex = digest.joinToString("") { "%02x".format(it) }
        if (list.size != 2048 || hex != WORD_LIST_SHA256) {
            throw RecoveryPhraseException(RecoveryPhraseException.Reason.WORD_LIST_DAMAGED, "The recovery word list is damaged; recovery phrases are unavailable")
        }
        return list
    }

    fun phrase(entropy: ByteArray): String {
        if (entropy.size != 32) throw RecoveryPhraseException(RecoveryPhraseException.Reason.BAD_ENTROPY, "Recovery entropy must be 256 bits")
        val bits = entropy + MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        try {
            return (0 until WORD_COUNT).joinToString(" ") { words[index(bits, it)] }
        } finally {
            bits.fill(0)
        }
    }

    /** NFKD, casefold, split on whitespace: exactly 24 tokens. */
    fun normalise(text: String): List<String> {
        if (text.length > MAX_INPUT) throw RecoveryPhraseException(RecoveryPhraseException.Reason.MALFORMED, "The recovery phrase is malformed")
        val tokens = Casefold.fold(Normalizer.normalize(text, Normalizer.Form.NFKD))
            .split(Regex("[\\s\\u001c-\\u001f]+")).filter { it.isNotEmpty() }
        if (tokens.size != WORD_COUNT) throw RecoveryPhraseException(RecoveryPhraseException.Reason.WRONG_WORD_COUNT, "A recovery phrase has exactly 24 words")
        return tokens
    }

    /** The 32 entropy bytes; the caller zeroes them. */
    fun entropy(text: String): ByteArray {
        val bits = ByteArray(33)
        try {
            normalise(text).forEachIndexed { position, token ->
                val index = lookup[token]
                    ?: throw RecoveryPhraseException(RecoveryPhraseException.Reason.UNKNOWN_WORD, "The recovery phrase contains a word that is not in the word list")
                for (b in 0 until 11) {
                    if (index and (1 shl (10 - b)) != 0) {
                        val bit = position * 11 + b
                        bits[bit / 8] = (bits[bit / 8].toInt() or (0x80 ushr (bit % 8))).toByte()
                    }
                }
            }
            val entropy = bits.copyOf(32)
            if (MessageDigest.getInstance("SHA-256").digest(entropy)[0] != bits[32]) {
                entropy.fill(0)
                throw RecoveryPhraseException(RecoveryPhraseException.Reason.CHECKSUM, "The recovery phrase checksum does not match; check the word order")
            }
            return entropy
        } finally {
            bits.fill(0)
        }
    }

    private fun index(bits: ByteArray, position: Int): Int {
        var value = 0
        for (b in 0 until 11) {
            val bit = position * 11 + b
            value = (value shl 1) or ((bits[bit / 8].toInt() ushr (7 - bit % 8)) and 1)
        }
        return value
    }
}
