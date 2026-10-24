import SwiftUI

/// The aurora's numbers, kept apart from the view so they are testable.
public enum AuroraStyle {
    /// Blob opacity; nil means no blobs (Reduce Transparency: the plain background).
    public static func blobOpacity(dark: Bool, reduceTransparency: Bool, increasedContrast: Bool) -> Double? {
        if reduceTransparency { return nil }
        let base = dark ? 0.45 : 0.35
        return increasedContrast ? base / 2 : base
    }
    /// Blur radius of the glow blobs, in points.
    public static let blurRadius: CGFloat = 100
}

/// `Palette.background` plus large, heavily blurred blue and orange glows (blue top-leading, orange
/// bottom-trailing, a blue/orange mix mid-right). Static: nothing animates. Content groups stay opaque on
/// top of it; only the glass controls let it through.
public struct AuroraBackground: View {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @Environment(\.colorSchemeContrast) private var contrast

    public init() {}

    public var body: some View {
        ZStack {
            Palette.background
            if let opacity = AuroraStyle.blobOpacity(dark: scheme == .dark, reduceTransparency: reduceTransparency,
                                                     increasedContrast: contrast == .increased) {
                GeometryReader { geo in
                    let w = geo.size.width, h = geo.size.height
                    ZStack {
                        Circle().fill(Palette.glowBlue)
                            .frame(width: w * 1.1, height: w * 1.1)
                            .position(x: w * 0.05, y: h * 0.08)
                        Circle().fill(Palette.glowOrange)
                            .frame(width: w * 1.05, height: w * 1.05)
                            .position(x: w * 0.98, y: h * 0.92)
                        Ellipse().fill(LinearGradient(colors: [Palette.glowBlue, Palette.glowOrange],
                                                      startPoint: .top, endPoint: .bottom))
                            .frame(width: w * 0.7, height: w * 0.85)
                            .position(x: w * 0.92, y: h * 0.48)
                    }
                    .blur(radius: AuroraStyle.blurRadius)
                    .opacity(opacity)
                }
                .accessibilityHidden(true)
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
    }
}

public extension View {
    /// The aurora behind this view, edge to edge.
    func lgkAuroraBackground() -> some View { background { AuroraBackground() } }

    /// A solid content group: groupSurface, a 1 px top highlight and a soft shadow so it lifts off the glow.
    func lgkGroupSurface(cornerRadius: CGFloat = 22) -> some View { modifier(GroupSurface(cornerRadius: cornerRadius)) }
}

struct GroupSurface: ViewModifier {
    let cornerRadius: CGFloat
    @Environment(\.colorScheme) private var scheme

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        content
            .background {
                shape.fill(Palette.groupSurface)
                    .shadow(color: .black.opacity(scheme == .dark ? 0.30 : 0.08), radius: 18, y: 6)
            }
            .overlay {
                shape.strokeBorder(LinearGradient(colors: [Color.white.opacity(scheme == .dark ? 0.12 : 0.9), .clear],
                                                  startPoint: .top, endPoint: .init(x: 0.5, y: 0.08)), lineWidth: 1)
                    .allowsHitTesting(false)
            }
    }
}
