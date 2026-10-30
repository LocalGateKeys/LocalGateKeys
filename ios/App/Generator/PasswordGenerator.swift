import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Desktop `password_tools.GeneratorOptions`: same defaults and character sets.
struct GeneratorOptions: Equatable, Sendable, Codable {
    enum Mode: String, Sendable, CaseIterable, Codable { case password, passphrase }
    var mode: Mode = .password
    var length = 20
    var lowercase = true
    var uppercase = true
    var digits = true
    var symbols = true
    var avoidAmbiguous = true
    var symbolSet = PasswordGenerator.defaultSymbols
    var exclude = ""
    var minDigits = 1
    var minSymbols = 1
    var words = 6
    var separator = "-"
    var capitalize = false
    var appendNumber = false
}

/// The generator's last-used options, kept in `AppSettings` (app group defaults) so new passwords start from
/// them. Options only: a generated value is never saved. Missing or unreadable data gives the desktop defaults.
struct GeneratorDefaults {
    let settings: AppSettings
    init(settings: AppSettings = .shared) { self.settings = settings }

    func load() -> GeneratorOptions {
        settings.generatorOptionsData.flatMap { try? JSONDecoder().decode(GeneratorOptions.self, from: $0) } ?? GeneratorOptions()
    }

    func save(_ options: GeneratorOptions) { settings.generatorOptionsData = try? JSONEncoder().encode(options) }

    func reset() { settings.generatorOptionsData = nil }
}

enum GeneratorError: Error, Equatable {
    /// Desktop wording.
    case noGroups, emptyGroup(String), badSeparator
    var message: String {
        switch self {
        case .noGroups: String(localized: "Select at least one character group")
        case .emptyGroup(let name):
            // `name` is the group's id (desktop wording); each group has its own sentence.
            switch name {
            case "lowercase letters": String(localized: "No usable lowercase letters remain after exclusions")
            case "uppercase letters": String(localized: "No usable uppercase letters remain after exclusions")
            case "digits": String(localized: "No usable digits remain after exclusions")
            case "symbols": String(localized: "No usable symbols remain after exclusions")
            default: String(localized: "No usable \(name) remain after exclusions")
            }
        case .badSeparator: String(localized: "Separator must be one of: dash, space, dot, underscore or none")
        }
    }
}

/// Port of desktop `generate_password` / `generate_passphrase`. All randomness comes from `RandomSource`.
struct PasswordGenerator: Sendable {
    static let defaultSymbols = "!@#$%^&*()-_=+[]{}:,.?"
    static let ambiguous: Set<Character> = Set("Il1O0o|`'\"")
    static let separators: [String] = ["-", " ", ".", "_", ""]
    static let lowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
    static let uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    static let digitChars = "0123456789"
    /// Desktop `_bounded_int(..., 8, 256)` and `max(3, min(words, 16))`.
    static let lengthRange = 8...256
    static let wordsRange = 3...16

    let random: any RandomSource

    func generate(_ o: GeneratorOptions) throws -> String {
        o.mode == .passphrase
            ? try passphrase(words: o.words, separator: o.separator, capitalize: o.capitalize, appendNumber: o.appendNumber)
            : try password(o)
    }

    func password(_ o: GeneratorOptions) throws -> String {
        var length = max(Self.lengthRange.lowerBound, min(o.length, Self.lengthRange.upperBound))
        var excluded = Set(o.exclude)
        if o.avoidAmbiguous { excluded.formUnion(Self.ambiguous) }
        var requested: [(String, String, Int)] = []
        if o.lowercase { requested.append(("lowercase letters", Self.lowercaseLetters, 1)) }
        if o.uppercase { requested.append(("uppercase letters", Self.uppercaseLetters, 1)) }
        if o.digits { requested.append(("digits", Self.digitChars, max(1, o.minDigits))) }
        if o.symbols { requested.append(("symbols", o.symbolSet, max(1, o.minSymbols))) }
        if requested.isEmpty { throw GeneratorError.noGroups }
        var groups: [([Character], Int)] = []
        for (name, alphabet, minimum) in requested {
            var seen = Set<Character>()
            let usable = alphabet.filter { !excluded.contains($0) && seen.insert($0).inserted }
            if usable.isEmpty { throw GeneratorError.emptyGroup(name) }
            groups.append((Array(usable), minimum))
        }
        length = max(length, groups.reduce(0) { $0 + $1.1 })
        var selected: [Character] = []
        for (alphabet, minimum) in groups { for _ in 0..<minimum { selected.append(choice(alphabet)) } }
        let pool = groups.flatMap(\.0)
        while selected.count < length { selected.append(choice(pool)) }
        // random.shuffle: Fisher-Yates from the end.
        for i in stride(from: selected.count - 1, to: 0, by: -1) { selected.swapAt(i, below(i + 1)) }
        return String(selected)
    }

    func passphrase(words: Int, separator: String, capitalize: Bool, appendNumber: Bool,
                    wordlist: [String]? = nil) throws -> String {
        guard Self.separators.contains(separator) else { throw GeneratorError.badSeparator }
        let count = max(Self.wordsRange.lowerBound, min(words, Self.wordsRange.upperBound))
        // Desktop `wordlist or load_wordlist()`; an empty list never reaches `choice`.
        let given = wordlist ?? Self.wordlist
        let list = given.isEmpty ? Self.fallbackWordlist : given
        var chosen = (0..<count).map { _ in choice(list) }
        if capitalize { chosen = chosen.map { $0.prefix(1).uppercased() + $0.dropFirst() } }
        var phrase = chosen.joined(separator: separator)
        if appendNumber { phrase += String(below(90) + 10) }
        return phrase
    }

    /// `secrets.randbelow(n)`: uniform via rejection sampling on 32-bit draws.
    func below(_ n: Int) -> Int {
        precondition(n > 0)
        let bound = UInt64(n), limit = (UInt64(1) << 32) / bound * bound
        while true {
            let b = random.bytes(count: 4)
            let v = UInt64(b[0]) << 24 | UInt64(b[1]) << 16 | UInt64(b[2]) << 8 | UInt64(b[3])
            if v < limit { return Int(v % bound) }
        }
    }

    func choice<T>(_ a: [T]) -> T { a[below(a.count)] }

    /// Desktop `load_wordlist`: the packaged list (a copy of `src/localvault/assets/eff_large_wordlist.txt`),
    /// sorted, unique, `[a-z]{3,12}` words only, comment lines skipped. A missing file or fewer than
    /// 1000 usable words gives the built-in `WORDLIST`, as on the desktop.
    static let wordlist: [String] = {
        let url = Bundle(for: BundleToken.self).url(forResource: "passphrase_wordlist", withExtension: "txt")
            ?? Bundle.main.url(forResource: "passphrase_wordlist", withExtension: "txt")
        return parseWordlist(url.flatMap { try? String(contentsOf: $0, encoding: .utf8) })
    }()

    static func parseWordlist(_ text: String?) -> [String] {
        guard let text else { return fallbackWordlist }
        let words = Set(text.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let w = line.trimmingCharacters(in: .whitespaces)
            if w.isEmpty || w.hasPrefix("#") { return nil }
            guard (3...12).contains(w.utf8.count), w.utf8.allSatisfy({ $0 >= 0x61 && $0 <= 0x7A }) else { return nil }
            return w
        })
        return words.count >= 1000 ? words.sorted() : fallbackWordlist
    }
}

private final class BundleToken {}
