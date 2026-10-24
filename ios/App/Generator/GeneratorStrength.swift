import Foundation

/// How strong the generator's options make a value, from the entropy of how it is drawn (not from the value
/// itself): `length × log2(charset)` for a password, `words × log2(wordlist)` (+ log2(90) for the number) for a
/// passphrase. Capitalising every word is not random, so it adds nothing.
enum GeneratorStrength {
    enum Level: Int, CaseIterable, Sendable {
        case weak, fair, strong, veryStrong

        var label: String {
            switch self {
            case .weak: "Weak"
            case .fair: "Fair"
            case .strong: "Strong"
            case .veryStrong: "Very strong"
            }
        }

        /// Filled segments of the 4-segment bar.
        var segments: Int { rawValue + 1 }
    }

    /// < 50 bits weak, < 70 fair, < 100 strong, else very strong.
    static func level(bits: Double) -> Level {
        switch bits {
        case ..<50: .weak
        case ..<70: .fair
        case ..<100: .strong
        default: .veryStrong
        }
    }

    /// A rough strength for a saved password, from the value itself: `length × log2(character pool)`, where
    /// repeated characters count once more at most and anything under 8 characters is weak. It cannot
    /// see dictionary words or reuse, so it errs only towards "stronger than it is" for clever-looking
    /// phrases; shown as an estimate.
    static func estimate(password: String) -> Level {
        let scalars = Array(password.unicodeScalars)
        guard scalars.count >= 8 else { return .weak }
        var pool = 0
        if scalars.contains(where: { ("a"..."z").contains($0) }) { pool += 26 }
        if scalars.contains(where: { ("A"..."Z").contains($0) }) { pool += 26 }
        if scalars.contains(where: { ("0"..."9").contains($0) }) { pool += 10 }
        if scalars.contains(where: { $0.isASCII && !$0.properties.isAlphabetic && !("0"..."9").contains($0) }) { pool += 33 }
        if scalars.contains(where: { !$0.isASCII }) { pool += 100 }
        let effectiveLength = min(scalars.count, Set(scalars).count * 2)
        return level(bits: Double(effectiveLength) * log2(Double(max(pool, 2))))
    }

    static func level(options: GeneratorOptions, wordlistCount: Int = PasswordGenerator.wordlist.count) -> Level {
        level(bits: entropyBits(options: options, wordlistCount: wordlistCount))
    }

    static func entropyBits(options o: GeneratorOptions, wordlistCount: Int) -> Double {
        switch o.mode {
        case .password:
            let charset = charsetSize(o)
            guard charset > 0 else { return 0 }
            let length = max(PasswordGenerator.lengthRange.lowerBound, min(o.length, PasswordGenerator.lengthRange.upperBound))
            return Double(length) * log2(Double(charset))
        case .passphrase:
            // The generator falls back to the built-in list when it is given an empty one.
            let size = wordlistCount > 0 ? wordlistCount : PasswordGenerator.fallbackWordlist.count
            let words = max(PasswordGenerator.wordsRange.lowerBound, min(o.words, PasswordGenerator.wordsRange.upperBound))
            return Double(words) * log2(Double(size)) + (o.appendNumber ? log2(90) : 0)
        }
    }

    /// Distinct characters the password draws from: the chosen groups minus look-alikes and exclusions,
    /// as `PasswordGenerator.password` filters them.
    static func charsetSize(_ o: GeneratorOptions) -> Int {
        var excluded = Set(o.exclude)
        if o.avoidAmbiguous { excluded.formUnion(PasswordGenerator.ambiguous) }
        var pool = Set<Character>()
        if o.lowercase { pool.formUnion(PasswordGenerator.lowercaseLetters) }
        if o.uppercase { pool.formUnion(PasswordGenerator.uppercaseLetters) }
        if o.digits { pool.formUnion(PasswordGenerator.digitChars) }
        if o.symbols { pool.formUnion(o.symbolSet) }
        return pool.subtracting(excluded).count
    }
}
