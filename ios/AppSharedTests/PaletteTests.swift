import XCTest
import UIKit
@testable import AppShared

/// The spec's "Glass skin" palette table (light / dark), verbatim.
final class PaletteTests: XCTestCase {
    static let spec: [(Palette.Token, UInt32, UInt32)] = [
        (.background, 0xEEF2F8, 0x0F1727),
        (.groupSurface, 0xFFFFFF, 0x18233A),
        (.innerTile, 0xF3F7FD, 0x22304A),
        (.separator, 0xE3E8F0, 0x2A3650),
        (.text, 0x101828, 0xF4F6FB),
        (.secondaryText, 0x5B6678, 0xA9B3C5),
        (.accent, 0x2B6FE0, 0x5AA0FF),
        (.accentText, 0x1F57B8, 0x7FB2FF),
        (.onAccent, 0xFFFFFF, 0x0F1727),
        (.glassFill, 0xFFFFFF, 0x242C3B),
        (.glassBorder, 0xD7E1EE, 0x3F4552),
        (.success, 0x1F7A4A, 0x7EE0A8),
        (.warning, 0xC27C0E, 0xFFCF80),
        (.danger, 0xC8372D, 0xFF7A70),
        (.glowBlue, 0x5B8CFF, 0x2B6FE0),
        (.glowOrange, 0xFF9F5A, 0xE8732A),
        (.identityTint, 0x7C5CE0, 0xB9A4FF),
    ]

    private func hex(_ c: UIColor, _ style: UIUserInterfaceStyle) -> UInt32 {
        let r = c.resolvedColor(with: UITraitCollection(userInterfaceStyle: style))
        var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
        XCTAssertTrue(r.getRed(&red, green: &green, blue: &blue, alpha: &alpha))
        XCTAssertEqual(alpha, 1, accuracy: 0.001)
        func b(_ v: CGFloat) -> UInt32 { UInt32((v * 255).rounded()) }
        return b(red) << 16 | b(green) << 8 | b(blue)
    }

    func test_palette_matches_spec_tokens() {
        XCTAssertEqual(Set(Palette.Token.allCases), Set(Self.spec.map(\.0)), "every token is in the spec table")
        for (token, light, dark) in Self.spec {
            let named = UIColor(named: token.rawValue, in: Palette.bundle, compatibleWith: nil)
            XCTAssertNotNil(named, "\(token.rawValue) missing from Colors.xcassets")
            guard let named else { continue }
            XCTAssertEqual(hex(named, .light), light, "\(token.rawValue) light")
            XCTAssertEqual(hex(named, .dark), dark, "\(token.rawValue) dark")
            XCTAssertEqual(hex(Palette.uiColor(token), .dark), dark, "\(token.rawValue) via Palette")
        }
    }
}
