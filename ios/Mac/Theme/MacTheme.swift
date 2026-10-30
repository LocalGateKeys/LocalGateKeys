import SwiftUI

/// The Windows app's colour tokens (`webui/src/styles/tokens.css`), dark and light.
struct MacTheme {
    let text, textMuted, textFaint, accent, onAccent, danger, success, warning: Color
    let wash1, wash2, wash3, washBase: Color
    let glass, glassBorder, glassHighlight, group, separator: Color
    /// The window shell (mockup): panel fill, inset cards, selected row, chips, row lines, status dot.
    let panel, panelBorder, panelHighlight, card, selection, chip, line, live: Color
    /// Links and copy icons (mockup `--link`).
    let link: Color
    /// Behind the Weak / Reused / Breached row tags (mockup `--dangerbg`).
    let dangerBackground: Color

    static let radiusGroup: CGFloat = 12, radiusCard: CGFloat = 18, radiusField: CGFloat = 10, gap: CGFloat = 12,
        radiusPanel: CGFloat = 14, shellGap: CGFloat = 10

    static let dark = MacTheme(
        text: .rgb(244, 246, 251), textMuted: .rgb(244, 246, 251, 0.6), textFaint: .rgb(244, 246, 251, 0.42),
        accent: .rgb(43, 111, 224), onAccent: .white, danger: .rgb(255, 122, 112), success: .rgb(126, 224, 168),
        warning: .rgb(255, 207, 128),
        wash1: .rgb(52, 102, 180, 0.55), wash2: .rgb(138, 78, 42, 0.45), wash3: .rgb(31, 122, 108, 0.45),
        washBase: .rgb(12, 20, 36),
        glass: .rgb(255, 255, 255, 0.09), glassBorder: .rgb(255, 255, 255, 0.2), glassHighlight: .rgb(255, 255, 255, 0.18),
        group: .rgb(18, 26, 44, 0.55), separator: .rgb(255, 255, 255, 0.09),
        panel: .rgb(10, 16, 30, 0.72), panelBorder: .rgb(255, 255, 255, 0.1), panelHighlight: .rgb(255, 255, 255, 0.08),
        card: .rgb(255, 255, 255, 0.035), selection: .rgb(255, 255, 255, 0.1),
        chip: .rgb(255, 255, 255, 0.08), line: .rgb(255, 255, 255, 0.07), live: .rgb(45, 189, 138),
        link: .rgb(143, 186, 255), dangerBackground: .rgb(255, 122, 112, 0.15))

    static let light = MacTheme(
        text: .rgb(19, 32, 58), textMuted: .rgb(19, 32, 58, 0.62), textFaint: .rgb(19, 32, 58, 0.45),
        accent: .rgb(11, 91, 211), onAccent: .white, danger: .rgb(180, 35, 54), success: .rgb(23, 107, 69),
        warning: .rgb(128, 91, 0),
        wash1: .rgb(120, 165, 235, 0.45), wash2: .rgb(240, 190, 150, 0.4), wash3: .rgb(140, 215, 200, 0.4),
        washBase: .rgb(238, 243, 250),
        glass: .rgb(255, 255, 255, 0.55), glassBorder: .rgb(19, 32, 58, 0.12), glassHighlight: .rgb(255, 255, 255, 0.8),
        group: .rgb(255, 255, 255, 0.62), separator: .rgb(19, 32, 58, 0.08),
        panel: .rgb(255, 255, 255, 0.6), panelBorder: .rgb(19, 32, 58, 0.12), panelHighlight: .rgb(255, 255, 255, 0.8),
        card: .rgb(255, 255, 255, 0.7), selection: .rgb(19, 32, 58, 0.07),
        chip: .rgb(19, 32, 58, 0.06), line: .rgb(19, 32, 58, 0.08), live: .rgb(45, 189, 138),
        link: .rgb(11, 91, 211), dangerBackground: .rgb(180, 35, 54, 0.1))

    static func `for`(_ scheme: ColorScheme) -> MacTheme { scheme == .dark ? dark : light }
}

extension Color {
    static func rgb(_ r: Double, _ g: Double, _ b: Double, _ a: Double = 1) -> Color {
        Color(.sRGB, red: r / 255, green: g / 255, blue: b / 255, opacity: a)
    }
}

private struct MacThemeKey: EnvironmentKey { static let defaultValue = MacTheme.dark }
extension EnvironmentValues {
    var macTheme: MacTheme { get { self[MacThemeKey.self] } set { self[MacThemeKey.self] = newValue } }
}

/// Puts the theme matching the current colour scheme into the environment.
struct ThemedByScheme: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    func body(content: Content) -> some View { content.environment(\.macTheme, MacTheme.for(scheme)) }
}
extension View { func macThemed() -> some View { modifier(ThemedByScheme()) } }

/// The colour wash behind everything: three radial glows on the base colour (as in the mockup).
struct WashBackground: View {
    @Environment(\.macTheme) private var theme
    var body: some View {
        GeometryReader { geo in
            let s = max(geo.size.width, geo.size.height)
            ZStack {
                theme.washBase
                RadialGradient(colors: [theme.wash1, .clear], center: UnitPoint(x: 0.08, y: 0), startRadius: 0, endRadius: s * 0.6)
                RadialGradient(colors: [theme.wash2, .clear], center: UnitPoint(x: 1, y: 0.45), startRadius: 0, endRadius: s * 0.5)
                RadialGradient(colors: [theme.wash3, .clear], center: UnitPoint(x: 0.35, y: 1), startRadius: 0, endRadius: s * 0.55)
            }
        }
        .ignoresSafeArea()
    }
}

/// A frosted glass panel with the token border and top highlight.
struct GlassPanel<Content: View>: View {
    @Environment(\.macTheme) private var theme
    var cornerRadius: CGFloat = MacTheme.radiusCard
    @ViewBuilder var content: Content
    var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content
            .background(.ultraThinMaterial, in: shape)
            .background(theme.glass, in: shape)
            .overlay(shape.strokeBorder(LinearGradient(colors: [theme.glassHighlight, theme.glassBorder],
                                                       startPoint: .top, endPoint: .bottom), lineWidth: 1))
            .shadow(color: .black.opacity(0.25), radius: 24, y: 10)
    }
}

/// A token-coloured text field container.
struct GlassFieldStyle: ViewModifier {
    @Environment(\.macTheme) private var theme
    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous).strokeBorder(theme.glassBorder))
            .foregroundStyle(theme.text)
    }
}
extension View { func glassField() -> some View { modifier(GlassFieldStyle()) } }

/// The accent-filled primary button.
struct AccentButtonStyle: ButtonStyle {
    @Environment(\.macTheme) private var theme
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .frame(maxWidth: .infinity).padding(.vertical, 9)
            .background(theme.accent.opacity(configuration.isPressed ? 0.8 : 1), in: RoundedRectangle(cornerRadius: MacTheme.radiusField))
            .foregroundStyle(theme.onAccent)
            .opacity(enabled ? 1 : 0.5)
    }
}

/// A quiet glass-coloured secondary button.
struct GlassButtonStyle: ButtonStyle {
    @Environment(\.macTheme) private var theme
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .frame(maxWidth: .infinity).padding(.vertical, 8)
            .background(theme.glass.opacity(configuration.isPressed ? 2 : 1), in: RoundedRectangle(cornerRadius: MacTheme.radiusField))
            .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField).strokeBorder(theme.glassBorder))
            .foregroundStyle(theme.text)
            .opacity(enabled ? 1 : 0.5)
    }
}
