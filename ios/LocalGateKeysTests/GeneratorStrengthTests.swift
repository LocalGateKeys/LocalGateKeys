import XCTest
import AppShared
@testable import LocalGateKeys

final class GeneratorStrengthTests: XCTestCase {
    private func log2(_ x: Double) -> Double { Foundation.log2(x) }

    func test_level_thresholds() {
        XCTAssertEqual(GeneratorStrength.level(bits: 0), .weak)
        XCTAssertEqual(GeneratorStrength.level(bits: 49.99), .weak)
        XCTAssertEqual(GeneratorStrength.level(bits: 50), .fair)
        XCTAssertEqual(GeneratorStrength.level(bits: 69.99), .fair)
        XCTAssertEqual(GeneratorStrength.level(bits: 70), .strong)
        XCTAssertEqual(GeneratorStrength.level(bits: 99.99), .strong)
        XCTAssertEqual(GeneratorStrength.level(bits: 100), .veryStrong)
        XCTAssertEqual(GeneratorStrength.Level.allCases.map(\.label), ["Weak", "Fair", "Strong", "Very strong"])
        XCTAssertEqual(GeneratorStrength.Level.allCases.map(\.segments), [1, 2, 3, 4])
    }

    func test_default_password_is_very_strong() {
        // Look-alikes removed: 24 lowercase (no l, o), 24 uppercase (no I, O), 8 digits (no 0, 1), 22 symbols.
        XCTAssertEqual(GeneratorStrength.charsetSize(GeneratorOptions()), 78)
        let bits = GeneratorStrength.entropyBits(options: GeneratorOptions(), wordlistCount: 7776)
        XCTAssertEqual(bits, 20 * log2(78), accuracy: 1e-9)
        XCTAssertEqual(GeneratorStrength.level(bits: bits), .veryStrong)
    }

    func test_known_password_cases() {
        var o = GeneratorOptions()
        o.lowercase = false; o.uppercase = false; o.symbols = false; o.length = 8
        // PIN without look-alikes: 8 digits, 8 long = 24 bits.
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), 24, accuracy: 1e-9)
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .weak)

        o = GeneratorOptions(); o.symbols = false; o.avoidAmbiguous = false; o.length = 12
        // 62 alphanumerics, 12 long: 71.45 bits.
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 0), 12 * log2(62), accuracy: 1e-9)
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 0), .strong)

        o.length = 10   // 59.5 bits
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 0), .fair)

        o = GeneratorOptions(); o.length = 3   // clamps to 8 like the generator
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 0), 8 * log2(78), accuracy: 1e-9)
        o.length = 999   // clamps to 256
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 0), 256 * log2(78), accuracy: 1e-9)
    }

    func test_symbols_shared_with_other_groups_count_once_and_exclusions_apply() {
        var o = GeneratorOptions(); o.lowercase = false; o.uppercase = false; o.digits = false
        o.symbolSet = "!!--"; o.avoidAmbiguous = false; o.length = 8
        XCTAssertEqual(GeneratorStrength.charsetSize(o), 2)
        o = GeneratorOptions(); o.avoidAmbiguous = false; o.exclude = "abc"
        XCTAssertEqual(GeneratorStrength.charsetSize(o), 26 + 26 + 10 + 22 - 3)
    }

    func test_no_groups_is_zero_bits() {
        var o = GeneratorOptions(); o.lowercase = false; o.uppercase = false; o.digits = false; o.symbols = false
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), 0)
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .weak)
    }

    func test_known_passphrase_cases() {
        var o = GeneratorOptions(); o.mode = .passphrase
        // Desktop default: 6 words of the EFF list (7776) = 77.5 bits.
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), 6 * log2(7776), accuracy: 1e-9)
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .strong)
        o.words = 3   // 38.8 bits
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .weak)
        o.words = 4   // 51.7 bits
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .fair)
        o.words = 8   // 103.4 bits
        XCTAssertEqual(GeneratorStrength.level(options: o, wordlistCount: 7776), .veryStrong)
        o.words = 40  // clamps to 16
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), 16 * log2(7776), accuracy: 1e-9)
    }

    func test_passphrase_number_adds_its_bits_and_capitalising_adds_none() {
        var o = GeneratorOptions(); o.mode = .passphrase; o.words = 4
        let base = GeneratorStrength.entropyBits(options: o, wordlistCount: 7776)
        o.appendNumber = true   // 10...99: 90 choices
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), base + log2(90), accuracy: 1e-9)
        o.appendNumber = false; o.capitalize = true   // every word capitalised: nothing random added
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 7776), base, accuracy: 1e-9)
    }

    func test_passphrase_with_an_empty_list_uses_the_fallback_size() {
        var o = GeneratorOptions(); o.mode = .passphrase; o.words = 6
        XCTAssertEqual(GeneratorStrength.entropyBits(options: o, wordlistCount: 0),
                       6 * log2(Double(PasswordGenerator.fallbackWordlist.count)), accuracy: 1e-9)
    }

    func test_settings_summary_names_the_strength() {
        XCTAssertEqual(SettingsView.summary(GeneratorOptions()), "Password, 20 characters")
        XCTAssertEqual(GeneratorStrength.level(options: GeneratorOptions()), .veryStrong,
                       "the default list size is used when none is given")
    }
}
