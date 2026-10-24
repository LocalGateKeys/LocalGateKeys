import SwiftUI

/// Glass for controls only (tab bar, + and avatar buttons). Content never sits on glass.
/// iOS 26+: Liquid Glass (`glassEffect`). iOS 17–25: `.ultraThinMaterial` with a 0.5 pt highlight border.
/// Reduce Transparency: the solid glass fill. Increase Contrast: a stronger border.
public struct GlassStyle<S: InsettableShape>: ViewModifier {
    let shape: S
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    public init(shape: S) { self.shape = shape }

    private var highContrast: Bool { contrast == .increased }

    public func body(content: Content) -> some View {
        if reduceTransparency {
            content
                .background(Palette.glassFill, in: shape)
                .overlay(shape.strokeBorder(Palette.glassBorder, lineWidth: highContrast ? 1.5 : 0.5))
        } else if #available(iOS 26, *) {
            content
                .glassEffect(.regular.interactive(), in: shape)
                .overlay { if highContrast { shape.strokeBorder(Palette.glassBorder, lineWidth: 1.5) } }
        } else {
            content
                .background(.ultraThinMaterial, in: shape)
                .overlay(shape.strokeBorder(highContrast ? Palette.glassBorder : Color.white.opacity(0.35),
                                            lineWidth: highContrast ? 1.5 : 0.5))
        }
    }
}

public extension View {
    func lgkGlass<S: InsettableShape>(in shape: S) -> some View { modifier(GlassStyle(shape: shape)) }
}

/// Groups glass controls so iOS 26 can blend them; a plain container below.
public struct LGKGlassContainer<Content: View>: View {
    let spacing: CGFloat
    let content: Content
    public init(spacing: CGFloat = 12, @ViewBuilder content: () -> Content) {
        self.spacing = spacing; self.content = content()
    }
    public var body: some View {
        if #available(iOS 26, *) {
            GlassEffectContainer(spacing: spacing) { content }
        } else {
            content
        }
    }
}
