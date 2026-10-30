import Foundation
import Crypto

/// A refused recovery phrase, with the message Windows (`vault.py` `RecoveryPhraseError`) gives. Never carries the
/// phrase or any of its words.
public struct RecoveryPhraseError: Error, Equatable, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }

    static let wrongCount = RecoveryPhraseError("A recovery phrase has exactly 24 words")
    static let malformed = RecoveryPhraseError("The recovery phrase is malformed")
    static let unknownWord = RecoveryPhraseError("The recovery phrase contains a word that is not in the word list")
    static let badChecksum = RecoveryPhraseError("The recovery phrase checksum does not match; check the word order")
    static let damagedList = RecoveryPhraseError("The recovery word list is damaged; recovery phrases are unavailable")
    public static let notThisVault = RecoveryPhraseError("This recovery phrase does not belong to this vault, or it was regenerated")
}

/// The 24-word BIP39 English recovery phrase (256 bits of entropy plus an 8-bit checksum), as Windows `vault.py`
/// `phrase_from_entropy`, `normalize_recovery_phrase` and `entropy_from_phrase`.
public enum BIP39 {
    public static let wordListSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    public static let wordCount = 24
    static let maxInputScalars = 2048

    private static let cached: Result<[String], RecoveryPhraseError> = Result { try load(englishText) }
        .mapError { $0 as? RecoveryPhraseError ?? .damagedList }

    /// The verified word list (`vault.bip39_words`); throws if its SHA-256 is not the Windows one.
    public static func words() throws -> [String] { try cached.get() }

    /// Splits `text` into words and checks there are 2048 and their digest (`"\n".join(words) + "\n"`).
    static func load(_ text: String) throws -> [String] {
        let words = text.split(whereSeparator: \.isWhitespace).map(String.init)
        let digest = SHA256.hash(data: Data((words.joined(separator: "\n") + "\n").utf8))
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        guard words.count == 2048, hex == wordListSHA256 else { throw RecoveryPhraseError.damagedList }
        return words
    }

    public static func phrase(entropy: Data) throws -> String {
        guard entropy.count == 32 else { throw RecoveryPhraseError("Recovery entropy must be 256 bits") }
        let list = try words()
        var bits = [UInt8](entropy)
        bits.append(Array(SHA256.hash(data: entropy))[0])
        defer { for i in bits.indices { bits[i] = 0 } }
        return (0..<wordCount).map { list[index(in: bits, at: $0)] }.joined(separator: " ")
    }

    /// NFKD, casefold and split on whitespace, as `normalize_recovery_phrase`.
    static func normalise(_ text: String) throws -> [String] {
        guard text.unicodeScalars.count <= maxInputScalars else { throw RecoveryPhraseError.malformed }
        let tokens = Casefold.fold(text.decomposedStringWithCompatibilityMapping)
            .split(whereSeparator: { $0.unicodeScalars.allSatisfy(isPythonSpace) }).map(String.init)
        guard tokens.count == wordCount else { throw RecoveryPhraseError.wrongCount }
        return tokens
    }

    public static func entropy(from text: String) throws -> Data {
        let list = try words()
        let lookup = Dictionary(uniqueKeysWithValues: list.enumerated().map { ($1, $0) })
        var bits = [UInt8](repeating: 0, count: 33)
        defer { for i in bits.indices { bits[i] = 0 } }
        for (position, token) in try normalise(text).enumerated() {
            guard let index = lookup[token] else { throw RecoveryPhraseError.unknownWord }
            for b in 0..<11 where index & (1 << (10 - b)) != 0 {
                let bit = position * 11 + b
                bits[bit / 8] |= UInt8(0x80 >> (bit % 8))
            }
        }
        var entropy = Data(bits[0..<32])
        guard Array(SHA256.hash(data: entropy))[0] == bits[32] else {
            entropy.resetBytes(in: 0..<entropy.count)
            throw RecoveryPhraseError.badChecksum
        }
        return entropy
    }

    /// Python `str.isspace`: Unicode White_Space plus the information separators U+001C-U+001F.
    private static func isPythonSpace(_ s: Unicode.Scalar) -> Bool {
        s.properties.isWhitespace || (0x1C...0x1F).contains(s.value)
    }

    /// The 11-bit word index at `position` in the 264-bit string `bits`.
    private static func index(in bits: [UInt8], at position: Int) -> Int {
        var value = 0
        for b in 0..<11 {
            let bit = position * 11 + b
            value = value << 1 | Int((bits[bit / 8] >> (7 - UInt8(bit % 8))) & 1)
        }
        return value
    }
}
