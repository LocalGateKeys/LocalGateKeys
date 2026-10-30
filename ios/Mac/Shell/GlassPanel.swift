import SwiftUI
import AppKit

/// The system blur behind a shell panel (`backdrop-filter` in the mockup).
struct VisualEffectBlur: NSViewRepresentable {
    var material: NSVisualEffectView.Material = .underWindowBackground

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.blendingMode = .behindWindow
        view.state = .followsWindowActiveState
        view.material = material
        return view
    }

    func updateNSView(_ view: NSVisualEffectView, context: Context) { view.material = material }
}

/// A window-shell panel (mockup `.panel`): blur, the panel token fill, a 1 pt border and a 1 pt inner top
/// highlight, radius 14.
struct ShellPanel<Content: View>: View {
    @Environment(\.macTheme) private var theme
    @Environment(\.colorScheme) private var scheme
    @ViewBuilder var content: Content

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: MacTheme.radiusPanel, style: .continuous)
        content
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .background(theme.panel, in: shape)
            .background(VisualEffectBlur(material: scheme == .dark ? .hudWindow : .underWindowBackground).clipShape(shape))
            .overlay(alignment: .top) {
                // Inner highlight: a 1 pt line just inside the top edge.
                Rectangle().fill(theme.panelHighlight).frame(height: 1)
                    .padding(.horizontal, MacTheme.radiusPanel).padding(.top, 1)
            }
            .overlay(shape.strokeBorder(theme.panelBorder, lineWidth: 1))
            .clipShape(shape)
    }
}

extension View {
    /// Fades a scroll view's last `height` points and lets its content scroll clear of the fade, so overflow
    /// reads as "more below" and the last row is never cut mid-glyph.
    func softBottomEdge(_ height: CGFloat = 24) -> some View {
        self.contentMargins(.bottom, height, for: .scrollContent)
            .mask {
                VStack(spacing: 0) {
                    Color.black
                    LinearGradient(colors: [.black, .clear], startPoint: .top, endPoint: .bottom).frame(height: height)
                }
            }
    }
}
