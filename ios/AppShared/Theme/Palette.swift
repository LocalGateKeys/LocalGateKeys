import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// The "Glass skin" palette (spec Part 2), stored as named colours with light and dark appearances in
/// `AppShared/Colors.xcassets`. Shared by the app and the AutoFill extension.
public enum Palette {
    public enum Token: String, CaseIterable, Sendable {
        case background, groupSurface, innerTile, separator, text, secondaryText
        case accent, accentText, onAccent, glassFill, glassBorder, success, warning, danger
        case glowBlue, glowOrange, identityTint
    }

    private final class Marker {}
    public static let bundle = Bundle(for: Marker.self)

#if canImport(UIKit)
    public static func uiColor(_ token: Token) -> UIColor {
        guard let c = UIColor(named: token.rawValue, in: bundle, compatibleWith: nil) else {
            preconditionFailure("Colors.xcassets is missing \(token.rawValue)")
        }
        return c
    }
#elseif canImport(AppKit) && !targetEnvironment(macCatalyst)
    public static func nsColor(_ token: Token) -> NSColor {
        guard let c = NSColor(named: token.rawValue, bundle: bundle) else {
            preconditionFailure("Colors.xcassets is missing \(token.rawValue)")
        }
        return c
    }
#endif

    public static func color(_ token: Token) -> Color { Color(token.rawValue, bundle: bundle) }

    /// Screen background.
    public static var background: Color { color(.background) }
    /// Solid grouped sections: lists, the Codes row, item detail.
    public static var groupSurface: Color { color(.groupSurface) }
    /// Tiles and icon wells inside a group.
    public static var innerTile: Color { color(.innerTile) }
    public static var separator: Color { color(.separator) }
    public static var text: Color { color(.text) }
    public static var secondaryText: Color { color(.secondaryText) }
    /// Fills and the selected tab. Never plain text on glass: use `accentText`.
    public static var accent: Color { color(.accent) }
    public static var accentText: Color { color(.accentText) }
    /// Text and icons on an accent fill: white in light mode, dark ink on the brighter dark-mode accent (4.5:1).
    public static var onAccent: Color { color(.onAccent) }
    /// Glass under Reduce Transparency.
    public static var glassFill: Color { color(.glassFill) }
    public static var glassBorder: Color { color(.glassBorder) }
    public static var success: Color { color(.success) }
    public static var warning: Color { color(.warning) }
    public static var danger: Color { color(.danger) }
    /// Aurora background glows (behind content only; never under text).
    public static var glowBlue: Color { color(.glowBlue) }
    public static var glowOrange: Color { color(.glowOrange) }
    /// Identity item tiles.
    public static var identityTint: Color { color(.identityTint) }
}
