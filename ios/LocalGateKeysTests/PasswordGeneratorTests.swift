import XCTest
import AppShared
@testable import LocalGateKeys

final class PasswordGeneratorTests: XCTestCase {
    func test_defaults_match_the_desktop() {
        let o = GeneratorOptions()
        XCTAssertEqual(o.mode, .password)
        XCTAssertEqual(o.length, 20)
        XCTAssertTrue(o.lowercase && o.uppercase && o.digits && o.symbols && o.avoidAmbiguous)
        XCTAssertEqual(o.symbolSet, "!@#$%^&*()-_=+[]{}:,.?")
        XCTAssertEqual(o.exclude, "")
        XCTAssertEqual(o.minDigits, 1); XCTAssertEqual(o.minSymbols, 1)
        XCTAssertEqual(o.words, 6); XCTAssertEqual(o.separator, "-")
        XCTAssertFalse(o.capitalize); XCTAssertFalse(o.appendNumber)
        XCTAssertEqual(PasswordGenerator.ambiguous, Set("Il1O0o|`'\""))
    }

    func test_password_uses_every_group_and_skips_ambiguous() throws {
        for seed in UInt8(0)..<40 {
            let pw = try PasswordGenerator(random: CountingRandom(start: seed)).generate(GeneratorOptions())
            XCTAssertEqual(pw.count, 20)
            XCTAssertTrue(pw.contains { $0.isLowercase }); XCTAssertTrue(pw.contains { $0.isUppercase })
            XCTAssertTrue(pw.contains { $0.isNumber })
            XCTAssertTrue(pw.contains { "!@#$%^&*()-_=+[]{}:,.?".contains($0) })
            XCTAssertFalse(pw.contains { PasswordGenerator.ambiguous.contains($0) })
        }
    }

    func test_fixed_random_is_deterministic_and_lengths_clamp() throws {
        let a = try PasswordGenerator(random: CountingRandom(start: 7)).generate(GeneratorOptions())
        let b = try PasswordGenerator(random: CountingRandom(start: 7)).generate(GeneratorOptions())
        XCTAssertEqual(a, b)
        var o = GeneratorOptions(); o.length = 3
        XCTAssertEqual(try PasswordGenerator(random: SystemRandomSource()).generate(o).count, 8)
        o.length = 999
        XCTAssertEqual(try PasswordGenerator(random: SystemRandomSource()).generate(o).count, 256)
        o = GeneratorOptions(); o.lowercase = false; o.uppercase = false; o.digits = false; o.symbols = false
        XCTAssertThrowsError(try PasswordGenerator(random: SystemRandomSource()).generate(o))
        o = GeneratorOptions(); o.lowercase = false; o.uppercase = false; o.symbols = false; o.length = 8
        XCTAssertTrue(try PasswordGenerator(random: SystemRandomSource()).generate(o).allSatisfy(\.isNumber), "PIN")
    }

    func test_passphrase_uses_the_desktop_word_list() throws {
        let words = PasswordGenerator.wordlist
        XCTAssertGreaterThanOrEqual(words.count, 1000)
        XCTAssertTrue(words.allSatisfy { $0.count >= 3 && $0.count <= 12 && $0.allSatisfy { ("a"..."z").contains(String($0)) } })
        var o = GeneratorOptions(); o.mode = .passphrase
        let phrase = try PasswordGenerator(random: CountingRandom()).generate(o)
        let parts = phrase.split(separator: "-").map(String.init)
        XCTAssertEqual(parts.count, 6)
        XCTAssertTrue(parts.allSatisfy { words.contains($0) })
        o.capitalize = true; o.appendNumber = true; o.separator = "."; o.words = 3
        let p2 = try PasswordGenerator(random: CountingRandom()).generate(o)
        XCTAssertEqual(p2.split(separator: ".").count, 3)
        XCTAssertTrue(p2.first!.isUppercase)
        XCTAssertTrue(Int(p2.suffix(2)).map { (10...99).contains($0) } ?? false)
    }
}

final class PasswordGeneratorG2Tests: XCTestCase {
    func test_missing_or_short_wordlist_falls_back_to_the_desktop_list() throws {
        XCTAssertEqual(PasswordGenerator.parseWordlist(nil), PasswordGenerator.fallbackWordlist)
        XCTAssertEqual(PasswordGenerator.parseWordlist(""), PasswordGenerator.fallbackWordlist)
        XCTAssertEqual(PasswordGenerator.parseWordlist("apple\nbanana\n"), PasswordGenerator.fallbackWordlist)
        XCTAssertEqual(PasswordGenerator.fallbackWordlist.first, "acorn")
        XCTAssertEqual(PasswordGenerator.fallbackWordlist.last, "zone")
        let p = try PasswordGenerator(random: SystemRandomSource())
            .passphrase(words: 4, separator: "-", capitalize: false, appendNumber: false, wordlist: [])
        XCTAssertEqual(p.split(separator: "-").count, 4)
        XCTAssertTrue(p.split(separator: "-").allSatisfy { PasswordGenerator.fallbackWordlist.contains(String($0)) })
    }

    func test_length_cap_matches_desktop() {
        XCTAssertEqual(PasswordGenerator.lengthRange, 8...256)
        XCTAssertEqual(PasswordGenerator.wordsRange, 3...16)
    }

    func test_generator_options_persist_and_reset_to_desktop_defaults() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "gen-\(UUID().uuidString)")!)
        let store = GeneratorDefaults(settings: settings)
        XCTAssertEqual(store.load(), GeneratorOptions(), "nothing saved: desktop defaults")
        var o = GeneratorOptions(); o.mode = .passphrase; o.length = 32; o.symbols = false; o.words = 9; o.separator = "_"
        store.save(o)
        XCTAssertEqual(GeneratorDefaults(settings: AppSettings(defaults: settings.defaults)).load(), o)
        store.reset()
        XCTAssertEqual(store.load(), GeneratorOptions())
        XCTAssertNil(settings.generatorOptionsData)
    }

    func test_corrupt_saved_options_fall_back_to_defaults() {
        let settings = AppSettings(defaults: UserDefaults(suiteName: "gen-\(UUID().uuidString)")!)
        settings.generatorOptionsData = Data("{nope".utf8)
        XCTAssertEqual(GeneratorDefaults(settings: settings).load(), GeneratorOptions())
    }
}
