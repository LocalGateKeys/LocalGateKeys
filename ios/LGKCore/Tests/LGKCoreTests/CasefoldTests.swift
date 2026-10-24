import XCTest
@testable import LGKCore

/// Golden values from Python `str.casefold()` (see Scripts/make_casefold.py).
final class CasefoldTests: XCTestCase {
    func hexes(_ s: String) -> [UInt32] { Casefold.fold(s).unicodeScalars.map(\.value) }

    func test_golden_cases() {
        let cases: [(String, [UInt32])] = [
            ("\u{FB01}", [0x66, 0x69]),                 // ﬁ
            ("\u{2C2F}", [0x2C5F]),                     // Glagolitic caudate chrivi (Unicode 14, Python 3.12)
            ("\u{A7C0}", [0xA7C1]),                     // Latin old polish o (Unicode 14)
            ("\u{149}", [0x2BC, 0x6E]),                 // ŉ
            ("\u{1F0}", [0x6A, 0x30C]),                 // ǰ
            ("\u{390}", [0x3B9, 0x308, 0x301]),         // ΐ
            ("\u{1E9B}", [0x1E61]),                     // ẛ
            ("\u{345}", [0x3B9]),                       // combining ypogegrammeni
            ("\u{1FB3}", [0x3B1, 0x3B9]),               // ᾳ
            ("\u{AB70}", [0x13A0]),                     // Cherokee small -> capital
            ("\u{13A0}", [0x13A0]),                     // Cherokee capital stays
            ("\u{13F8}", [0x13F0]),                     // Cherokee small ye -> capital
            ("\u{130}", [0x69, 0x307]),                 // İ
            ("\u{DF}", [0x73, 0x73]),                   // ß
            ("\u{1E9E}", [0x73, 0x73]),                 // ẞ
            ("\u{3A3}", [0x3C3]), ("\u{3C3}", [0x3C3]), ("\u{3C2}", [0x3C3]),
            ("AbC-z9", [0x61, 0x62, 0x63, 0x2D, 0x7A, 0x39]),
            ("\u{E9}", [0xE9]),                         // é stays precomposed
            ("e\u{301}", [0x65, 0x301]),                // decomposed stays decomposed
            ("\u{C9}", [0xE9]),
            ("\u{212A}", [0x6B]),                       // Kelvin sign
            ("\u{3D0}", [0x3B2]),                       // ϐ
            ("\u{1E9E}x", [0x73, 0x73, 0x78]),
            ("\u{10400}", [0x10428]),                   // Deseret
            ("", []),
        ]
        for (input, want) in cases {
            XCTAssertEqual(hexes(input), want, "input \(input.unicodeScalars.map { String($0.value, radix: 16) })")
        }
    }
}
