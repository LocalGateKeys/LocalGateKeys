import Foundation

/// A port of the desktop's zxcvbn-style `password_tools.estimate_strength` (dictionary with l33t,
/// reversal and capitals; sequences; repeats; keyboard walks; dates; brute force; the minimum-guesses
/// sequence and the 0...4 score). Pinned by tests/vectors/strength/vectors.json, which the desktop
/// generates (scripts/gen_strength_vectors.py).
///
/// Python strings are code point sequences, so every offset, length and slice here works on Unicode
/// scalars, and the character tests follow Python's `str.isalpha/islower/isupper/isdigit/isspace`,
/// `str.lower` and the `re` module's `\d`, `\s` and `.`.
public enum PasswordStrength {

    /// Desktop `estimate_strength(password)`: the 0...4 score and the guess count.
    public static func estimate(_ password: String) -> (score: Int, guesses: Double) {
        let guesses = estimate(Array(password.unicodeScalars).map(\.value), depth: 0)
        return (score(guesses), guesses)
    }

    // MARK: constants

    private static let minGuessesBeforeGrowingSequence = 10_000.0
    private static let minSubmatchSingle = 10.0
    private static let minSubmatchMulti = 50.0
    private static let bruteforceCardinality = 10.0
    private static let referenceYear = 2026
    private static let minYearSpace = 20
    private static let maxAnalyzed = 100
    private static let keyboardStarts = 47.0
    private static let keyboardAverageDegree = 4.6

    static func score(_ guesses: Double) -> Int {
        if guesses < 1e3 + 5 { return 0 }
        if guesses < 1e6 + 5 { return 1 }
        if guesses < 1e8 + 5 { return 2 }
        if guesses < 1e10 + 5 { return 3 }
        return 4
    }

    private struct Match {
        let pattern: Pattern
        let i: Int
        let j: Int
        let guesses: Double
        var length: Int { j - i + 1 }
    }

    private enum Pattern { case dictionary, sequence, repeating, spatial, date, bruteforce }

    private typealias Text = [UInt32]

    // MARK: estimate

    private static func estimate(_ password: Text, depth: Int) -> Double {
        let analyzed = Array(password.prefix(maxAnalyzed))
        let overflow = password.count - analyzed.count
        var matches: [Match] = []
        if !analyzed.isEmpty {
            matches += dictionaryMatches(analyzed)
            matches += sequenceMatches(analyzed)
            matches += repeatMatches(analyzed, depth: depth)
            matches += spatialMatches(analyzed)
            matches += dateMatches(analyzed)
        }
        var guesses = mostGuessableSequence(analyzed, matches)
        if overflow > 0 { guesses *= pow(bruteforceCardinality, Double(overflow)) }
        return max(1.0, guesses)
    }

    // MARK: Python character tests

    private static func props(_ cp: UInt32) -> Unicode.Scalar.Properties? { Unicode.Scalar(cp)?.properties }

    /// `str.isalpha`: general categories Lu, Ll, Lt, Lm, Lo.
    private static func isAlpha(_ cp: UInt32) -> Bool {
        switch props(cp)?.generalCategory {
        case .uppercaseLetter?, .lowercaseLetter?, .titlecaseLetter?, .modifierLetter?, .otherLetter?: return true
        default: return false
        }
    }

    /// `str.islower` / `str.isupper` for one character: the derived Lowercase / Uppercase properties.
    private static func isLower(_ cp: UInt32) -> Bool { props(cp)?.isLowercase ?? false }
    private static func isUpper(_ cp: UInt32) -> Bool { props(cp)?.isUppercase ?? false }

    /// `str.isdigit`: Numeric_Type Decimal or Digit.
    private static func isDigit(_ cp: UInt32) -> Bool {
        switch props(cp)?.numericType {
        case .decimal?, .digit?: return true
        default: return false
        }
    }

    /// `re` `\d` on a str: a Unicode decimal digit (Nd).
    private static func isDecimal(_ cp: UInt32) -> Bool { props(cp)?.generalCategory == .decimalNumber }

    /// `re` `\s` on a str (`str.isspace`: bidi WS/B/S or category Zs).
    private static func isSpace(_ cp: UInt32) -> Bool {
        switch cp {
        case 0x09...0x0D, 0x1C...0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
            return true
        default:
            return false
        }
    }

    private static func string(_ t: some Collection<UInt32>) -> String {
        var s = String.UnicodeScalarView()
        for cp in t { if let u = Unicode.Scalar(cp) { s.append(u) } }
        return String(s)
    }

    /// `str.lower()` (full, locale-independent lower-casing).
    private static func lower(_ t: Text) -> Text { Array(string(t).lowercased().unicodeScalars).map(\.value) }

    // MARK: dictionary

    private static let commonRank: [String: Int] = {
        var m: [String: Int] = [:]
        for (index, value) in StrengthLists.common.enumerated() {
            let key = string(lower(Array(value.unicodeScalars).map(\.value)))
            if m[key] == nil { m[key] = index + 1 }
        }
        return m
    }()

    private static let wordSet: Set<String> = Set(StrengthLists.words)

    private static func dictionaryRank(_ candidate: String) -> Double? {
        if let rank = commonRank[candidate] { return Double(rank) }
        if wordSet.contains(candidate) { return Double(StrengthLists.wordRank) }
        return nil
    }

    private static let l33tReverse: [UInt32: [UInt32]] = {
        let table: [(Character, String)] = [
            ("a", "4@"), ("b", "8"), ("c", "({[<"), ("e", "3"), ("g", "69"), ("i", "1!|"), ("l", "1|7"), ("o", "0"),
            ("s", "$5"), ("t", "+7"), ("x", "%"), ("z", "2"),
        ]
        var m: [UInt32: [UInt32]] = [:]
        for (letter, subs) in table {
            for sub in subs.unicodeScalars { m[sub.value, default: []].append(letter.unicodeScalars.first!.value) }
        }
        return m
    }()

    /// Desktop `_l33t_variants` (limit 32): candidates with l33t characters restored, and the substitution count.
    private static func l33tVariants(_ lowerToken: Text, limit: Int = 32) -> [(Text, Int)] {
        guard lowerToken.contains(where: { l33tReverse[$0] != nil }) else { return [] }
        var variants: [(Text, Int)] = [([], 0)]
        for ch in lowerToken {
            if let options = l33tReverse[ch] {
                var next: [(Text, Int)] = []
                outer: for (prefix, count) in variants {
                    for letter in options {
                        if next.count >= limit { break outer }
                        next.append((prefix + [letter], count + 1))
                    }
                }
                variants = next
            } else {
                variants = variants.map { ($0.0 + [ch], $0.1) }
            }
        }
        return variants.filter { $0.0 != lowerToken }
    }

    private static func uppercaseVariations(_ token: ArraySlice<UInt32>) -> Double {
        let letters = token.filter(isAlpha)
        if letters.isEmpty || letters.allSatisfy(isLower) { return 1 }
        if (isUpper(token.first!) && letters.dropFirst().allSatisfy(isLower))
            || (isUpper(token.last!) && letters.dropLast().allSatisfy(isLower))
            || letters.allSatisfy(isUpper) {
            return 2
        }
        let upper = letters.filter(isUpper).count
        let lowerCount = letters.count - upper
        var sum = 0.0
        if min(upper, lowerCount) >= 1 {
            for k in 1...min(upper, lowerCount) { sum += comb(upper + lowerCount, k) }
        }
        return max(2, sum)
    }

    private static func dictionaryMatches(_ password: Text) -> [Match] {
        var matches: [Match] = []
        let n = password.count
        for i in 0..<n {
            var j = i + 2
            while j < n {
                defer { j += 1 }
                let token = password[i...j]
                let low = lower(Array(token))
                let reversed = Array(low.reversed())
                var candidates: [(Text, Int, Bool)] = [(low, 0, false), (reversed, 0, true)]
                candidates += l33tVariants(low).map { ($0.0, $0.1, false) }
                candidates += l33tVariants(reversed).map { ($0.0, $0.1, true) }
                var best: Double?
                for (candidate, substitutions, isReversed) in candidates {
                    guard let rank = dictionaryRank(string(candidate)) else { continue }
                    var guesses = rank * uppercaseVariations(token)
                    if substitutions > 0 { guesses *= max(2, pow(2, Double(substitutions))) }
                    if isReversed { guesses *= 2 }
                    if best == nil || guesses < best! { best = guesses }
                }
                if let best { matches.append(Match(pattern: .dictionary, i: i, j: j, guesses: best)) }
            }
        }
        return matches
    }

    // MARK: sequences

    private static func charClass(_ cp: UInt32) -> Int {
        if isLower(cp) { return 0 }
        if isUpper(cp) { return 1 }
        if isDigit(cp) { return 2 }
        return 3
    }

    private static func sequenceMatches(_ password: Text) -> [Match] {
        var matches: [Match] = []
        let n = password.count
        var i = 0
        while i < n - 2 {
            var j = i + 1
            let delta = Int(password[j]) - Int(password[i])
            if abs(delta) != 1 || charClass(password[i]) == 3 || charClass(password[i]) != charClass(password[j]) {
                i += 1
                continue
            }
            while j + 1 < n && Int(password[j + 1]) - Int(password[j]) == delta
                && charClass(password[j + 1]) == charClass(password[i]) {
                j += 1
            }
            if j - i + 1 >= 3 {
                let first = password[i]
                let base: Double
                if "aAzZ019".unicodeScalars.contains(where: { $0.value == first }) {
                    base = 4
                } else if isDigit(first) {
                    base = 10
                } else {
                    base = 26
                }
                let guesses = base * Double(j - i + 1) * (delta < 0 ? 2 : 1)
                matches.append(Match(pattern: .sequence, i: i, j: j, guesses: guesses))
                i = j
            }
            i += 1
        }
        return matches
    }

    // MARK: repeats (desktop `(.+?)\1+` and `(.+)\1+`, by hand; `.` is anything but "\n")

    /// Full copies of `password[start..<start+base]` that follow it.
    private static func copies(_ p: Text, _ start: Int, _ base: Int) -> Int {
        var count = 0
        var at = start + base
        while at + base <= p.count && p[start..<(start + base)] == p[at..<(at + base)] {
            count += 1
            at += base
        }
        return count
    }

    private static func dotRun(_ p: Text, _ start: Int) -> Int {
        var k = start
        while k < p.count && p[k] != 0x0A { k += 1 }
        return k - start
    }

    /// (start, end exclusive, base length)
    private static func lazySearch(_ p: Text, from position: Int) -> (Int, Int, Int)? {
        for s in position..<p.count {
            let run = dotRun(p, s)
            if run < 1 { continue }
            for len in 1...run {
                if s + 2 * len > p.count { break }
                let c = copies(p, s, len)
                if c >= 1 { return (s, s + len * (c + 1), len) }
            }
        }
        return nil
    }

    private static func greedyAt(_ p: Text, _ s: Int) -> (Int, Int, Int)? {
        let run = dotRun(p, s)
        if run < 1 { return nil }
        for len in stride(from: run, through: 1, by: -1) {
            if s + 2 * len > p.count { continue }
            let c = copies(p, s, len)
            if c >= 1 { return (s, s + len * (c + 1), len) }
        }
        return nil
    }

    private static func repeatMatches(_ password: Text, depth: Int) -> [Match] {
        var matches: [Match] = []
        if depth > 2 { return matches }
        var position = 0
        while position < password.count {
            guard let lazy = lazySearch(password, from: position) else { break }
            var candidates = [lazy]
            if let greedy = greedyAt(password, lazy.0), greedy.1 > lazy.1 { candidates.append(greedy) }
            var chosen: (Int, Int, Int)?
            var chosenGuesses = Double.infinity
            for c in candidates {
                let repeatCount = (c.1 - c.0) / c.2
                if repeatCount < 2 { continue }
                let baseGuesses = estimate(Array(password[c.0..<(c.0 + c.2)]), depth: depth + 1)
                let guesses = baseGuesses * Double(repeatCount)
                if guesses < chosenGuesses {
                    chosen = c
                    chosenGuesses = guesses
                }
            }
            guard let chosen else {
                position = lazy.0 + 1
                continue
            }
            matches.append(Match(pattern: .repeating, i: chosen.0, j: chosen.1 - 1, guesses: chosenGuesses))
            position = chosen.1
        }
        return matches
    }

    // MARK: keyboard walks

    private struct Key { let row: Int; let col: Int; let shifted: Bool }

    private static let keyPositions: [UInt32: Key] = {
        let rows = ["`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./"]
        let shifted = ["~!@#$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?"]
        var m: [UInt32: Key] = [:]
        for r in rows.indices {
            for (c, ch) in rows[r].unicodeScalars.enumerated() { m[ch.value] = Key(row: r, col: c, shifted: false) }
            for (c, ch) in shifted[r].unicodeScalars.enumerated() { m[ch.value] = Key(row: r, col: c, shifted: true) }
        }
        return m
    }()

    private static func adjacent(_ a: (Int, Int), _ b: (Int, Int)) -> (Int, Int)? {
        let dr = b.0 - a.0, dc = b.1 - a.1
        if dr == 0 && abs(dc) == 1 { return (0, dc) }
        if dr == 1 && (dc == 0 || dc == -1) { return (1, dc) }
        if dr == -1 && (dc == 0 || dc == 1) { return (-1, dc) }
        return nil
    }

    private static func spatialGuesses(_ length: Int, _ turns: Int, _ shifted: Int) -> Double {
        var guesses = 0.0
        if length >= 2 {
            for i in 2...length {
                let top = min(turns, i - 1)
                if top < 1 { continue }
                for j in 1...top {
                    guesses += comb(i - 1, j - 1) * keyboardStarts * pow(keyboardAverageDegree, Double(j))
                }
            }
        }
        if shifted > 0 {
            let unshifted = length - shifted
            if unshifted == 0 {
                guesses *= 2
            } else {
                var sum = 0.0
                for k in 1...min(shifted, unshifted) { sum += comb(length, k) }
                guesses *= sum
            }
        }
        return max(guesses, 1)
    }

    private static func spatialMatches(_ password: Text) -> [Match] {
        var matches: [Match] = []
        let n = password.count
        var i = 0
        while i < n - 2 {
            guard let start = keyPositions[password[i]] else {
                i += 1
                continue
            }
            var j = i
            var turns = 0
            var last: (Int, Int)?
            var shifted = start.shifted ? 1 : 0
            var previous = (start.row, start.col)
            while j + 1 < n {
                guard let next = keyPositions[password[j + 1]],
                      let direction = adjacent(previous, (next.row, next.col)) else { break }
                if last == nil || last! != direction {
                    turns += 1
                    last = direction
                }
                if next.shifted { shifted += 1 }
                previous = (next.row, next.col)
                j += 1
            }
            if j - i + 1 >= 3 {
                matches.append(Match(pattern: .spatial, i: i, j: j, guesses: spatialGuesses(j - i + 1, turns, shifted)))
                i = j
            }
            i += 1
        }
        return matches
    }

    // MARK: dates

    private static func validDate(_ day0: Int, _ month0: Int, _ year0: Int) -> Int? {
        var day = day0, month = month0
        if (1...12).contains(month) && (1...31).contains(day) {
            // as given
        } else if (1...12).contains(day) && (1...31).contains(month) {
            swap(&day, &month)
        } else {
            return nil
        }
        var year = year0
        if year < 100 { year += year > 30 ? 1900 : 2000 }
        guard (1900...2050).contains(year) else { return nil }
        return year
    }

    /// Python `int()` of decimal digits (saturating; dates never need more than 8 digits).
    private static func number(_ d: ArraySlice<UInt32>) -> Int {
        var v = 0
        for cp in d {
            let digit = Int(props(cp)?.numericValue ?? 0)
            v = v > Int.max / 20 ? v : v * 10 + digit
        }
        return v
    }

    private static let dateSplits: [Int: [(Int, Int)]] = [
        4: [(1, 2), (2, 3)],
        5: [(1, 3), (2, 3)],
        6: [(1, 2), (2, 4), (4, 5)],
        7: [(1, 3), (2, 3), (4, 5), (4, 6)],
        8: [(2, 4), (4, 6)],
    ]

    /// Years of the desktop `_date_candidates`, in order.
    private static func dateCandidates(_ token: ArraySlice<UInt32>) -> [Int] {
        var out: [Int] = []
        let t = Array(token)
        if t.count == 4 && t.allSatisfy(isDigit) {
            let year = number(t[...])
            if (1900...2050).contains(year) { out.append(year) }
        }
        for (a, b) in dateSplits[t.count] ?? [] {
            let parts = [t[0..<a], t[a..<b], t[b...]]
            guard parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(isDigit) }) else { continue }
            let p0 = number(parts[0]), p1 = number(parts[1]), p2 = number(parts[2])
            for (day, month, year) in [(p1, p2, p0), (p0, p1, p2)] {
                if let y = validDate(day, month, year) { out.append(y) }
            }
        }
        return out
    }

    private static func dateGuesses(_ year: Int, separated: Bool) -> Double {
        let g = Double(max(abs(year - referenceYear), minYearSpace) * 365)
        return separated ? g * 4 : g
    }

    private static func decimalRun(_ p: Text, _ from: Int) -> Int {
        var k = from
        while k < p.count && isDecimal(p[k]) { k += 1 }
        return k - from
    }

    private static let dateSeparators: Set<UInt32> = [0x2F, 0x5C, 0x5F, 0x2E, 0x2D]

    /// `(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})` matched at `s`: end and groups 1, 3, 4.
    private static func separatedDateAt(_ p: Text, _ s: Int)
        -> (end: Int, g1: ArraySlice<UInt32>, g3: ArraySlice<UInt32>, g4: ArraySlice<UInt32>)? {
        let r1 = min(decimalRun(p, s), 4)
        if r1 < 1 { return nil }
        for l1 in stride(from: r1, through: 1, by: -1) {
            let sepAt = s + l1
            if sepAt >= p.count { continue }
            let sep = p[sepAt]
            if !(isSpace(sep) || dateSeparators.contains(sep)) { continue }
            let r3 = min(decimalRun(p, sepAt + 1), 2)
            if r3 < 1 { continue }
            for l3 in stride(from: r3, through: 1, by: -1) {
                let sep2 = sepAt + 1 + l3
                if sep2 >= p.count || p[sep2] != sep { continue }
                let l4 = min(decimalRun(p, sep2 + 1), 4)
                if l4 < 1 { continue }
                return (sep2 + 1 + l4, p[s..<sepAt], p[(sepAt + 1)..<sep2], p[(sep2 + 1)..<(sep2 + 1 + l4)])
            }
        }
        return nil
    }

    private static func dateMatches(_ password: Text) -> [Match] {
        var matches: [Match] = []
        var at = 0
        while at < password.count {
            let run = decimalRun(password, at)
            if run < 4 {
                at += max(run, 1)
                continue
            }
            let start = at
            let token = password[at..<(at + min(run, 8))]
            at += token.count
            for length in stride(from: token.count, through: 4, by: -1) {
                for offset in 0...(token.count - length) {
                    let sub = token[(start + offset)..<(start + offset + length)]
                    let years = dateCandidates(sub)
                    guard var year = years.first else { continue }
                    for y in years where abs(y - referenceYear) < abs(year - referenceYear) { year = y }
                    let i = start + offset
                    matches.append(Match(pattern: .date, i: i, j: i + length - 1,
                                         guesses: dateGuesses(year, separated: false)))
                }
            }
        }
        var s = 0
        while s < password.count {
            guard let found = separatedDateAt(password, s) else {
                s += 1
                continue
            }
            let p0 = number(found.g1), p1 = number(found.g3), p2 = number(found.g4)
            for (day, month, year) in [(p1, p2, p0), (p0, p1, p2), (p1, p0, p2)] {
                guard let y = validDate(day, month, year) else { continue }
                matches.append(Match(pattern: .date, i: s, j: found.end - 1, guesses: dateGuesses(y, separated: true)))
                break
            }
            s = found.end
        }
        return matches
    }

    // MARK: the cheapest sequence

    private static func bruteforce(_ i: Int, _ j: Int) -> Match {
        let len = j - i + 1
        let minimum = len == 1 ? minSubmatchSingle : minSubmatchMulti
        return Match(pattern: .bruteforce, i: i, j: j, guesses: max(pow(bruteforceCardinality, Double(len)), minimum))
    }

    /// An insertion-ordered map from sequence length (Python dict semantics: replacing keeps the position).
    private struct Ordered<V> {
        var keys: [Int] = []
        var values: [Int: V] = [:]
        subscript(key: Int) -> V? {
            get { values[key] }
            set {
                if values[key] == nil { keys.append(key) }
                values[key] = newValue
            }
        }
    }

    private static func mostGuessableSequence(_ password: Text, _ matches: [Match]) -> Double {
        let n = password.count
        if n == 0 { return 1 }
        var byEnd = [[Match]](repeating: [], count: n)
        for m in matches { byEnd[m.j].append(m) }
        var optimalM = [Ordered<Match>](repeating: Ordered(), count: n)
        var optimalPi = [Ordered<Double>](repeating: Ordered(), count: n)
        var optimalG = [Ordered<Double>](repeating: Ordered(), count: n)

        func floored(_ m: Match) -> Double {
            if m.i == 0 && m.j == n - 1 { return m.guesses }
            return max(m.guesses, m.length == 1 ? minSubmatchSingle : minSubmatchMulti)
        }

        func update(_ m: Match, _ length: Int) {
            let k = m.j
            var pi = floored(m)
            if length > 1 { pi *= optimalPi[m.i - 1][length - 1]! }
            var g = factorial(length) * pi
            if length > 1 { g += pow(minGuessesBeforeGrowingSequence, Double(length - 1)) }
            for competingLength in optimalG[k].keys {
                if competingLength > length { continue }
                if optimalG[k][competingLength]! <= g { return }
            }
            optimalG[k][length] = g
            optimalM[k][length] = m
            optimalPi[k][length] = pi
        }

        for k in 0..<n {
            for m in byEnd[k] {
                if m.i > 0 {
                    for length in optimalM[m.i - 1].keys { update(m, length + 1) }
                } else {
                    update(m, 1)
                }
            }
            update(bruteforce(0, k), 1)
            if k >= 1 {
                for i in 1...k {
                    let chunk = bruteforce(i, k)
                    let previous = optimalM[i - 1]
                    for length in previous.keys where previous[length]!.pattern != .bruteforce {
                        update(chunk, length + 1)
                    }
                }
            }
        }
        var best = Double.infinity
        for length in optimalG[n - 1].keys { best = min(best, optimalG[n - 1][length]!) }
        return best
    }

    // MARK: integer helpers (Python ints converted to float)

    private static func comb(_ n: Int, _ k: Int) -> Double {
        if k < 0 || k > n { return 0 }
        let k = min(k, n - k)
        var r = 1.0
        if k > 0 { for x in 0..<k { r = r * Double(n - x) / Double(x + 1) } }
        return r.rounded()
    }

    private static func factorial(_ n: Int) -> Double {
        var r = 1.0
        if n >= 2 { for x in 2...n { r *= Double(x) } }
        return r
    }
}
