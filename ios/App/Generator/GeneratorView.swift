import SwiftUI
import AppShared

/// The password generator sheet, in the glass skin: aurora behind, a solid hero card with the value and its
/// strength, glass controls (regenerate, copy, Password | Passphrase), and a solid options card.
struct GeneratorView: View {
    let onUse: @MainActor (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var model = GeneratorModel()

    init(onUse: @escaping @MainActor (String) -> Void) { self.onUse = onUse }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    GeneratorHeroCard(model: model)
                    controls
                    GeneratorOptionsCard(options: $model.options)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .scrollDismissesKeyboard(.interactively)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .lgkAuroraBackground()
            .navigationTitle("Generator")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use") { model.use(dismiss: { dismiss() }, deliver: onUse) }
                        .fontWeight(.semibold)
                        .lgkProminentButton()
                        .disabled(!model.canUse)
                }
            }
            .onAppear { model.start() }
        }
        .lgkAuroraBackground()
        .presentationBackground { AuroraBackground() }
    }

    /// Password | Passphrase, then regenerate and copy. Stacks when the text is too large for one row.
    private var controls: some View {
        LGKGlassContainer {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) {
                    GlassModePicker(mode: $model.options.mode)
                    actionButtons
                }
                VStack(spacing: 12) {
                    GlassModePicker(mode: $model.options.mode)
                    actionButtons
                }
            }
        }
    }

    private var actionButtons: some View {
        HStack(spacing: 12) {
            Button { withAnimation(.snappy) { model.regenerate() } } label: {
                GlassCircleLabel { Image(systemName: "arrow.clockwise").font(.system(size: 18, weight: .semibold)) }
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Generate again")
            Button { model.copy() } label: {
                GlassCircleLabel {
                    Image(systemName: model.copied ? "checkmark" : "doc.on.doc").font(.system(size: 18, weight: .semibold))
                        .contentTransition(.symbolEffect(.replace))
                }
            }
            .buttonStyle(.plain)
            .disabled(model.value.isEmpty)
            .accessibilityLabel(model.copied ? String(localized: "Copied") : String(localized: "Copy"))
        }
    }
}

// MARK: hero

/// The value, large and coloured by character class, with its strength. Solid, never glass. Tap to copy.
struct GeneratorHeroCard: View {
    let model: GeneratorModel
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(model.options.mode == .password ? String(localized: "Password") : String(localized: "Passphrase"))
                    .font(.subheadline).foregroundStyle(Palette.secondaryText)
                Spacer()
                Text(model.copied ? String(localized: "Copied") : String(localized: "Tap to copy"))
                    .font(.footnote).foregroundStyle(model.copied ? Palette.success : Palette.secondaryText)
                    .accessibilityHidden(true)
            }
            if let error = model.error {
                Text(error).font(.body).foregroundStyle(Palette.danger)
                    .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
            } else {
                Text(Self.colored(model.value, symbol: symbolColor))
                    .font(.system(.title2, design: .monospaced).weight(.semibold))
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, minHeight: 60, alignment: .leading)
                    .contentTransition(.opacity)
                    .accessibilityLabel(model.value)
                    .accessibilityHint("Double-tap to copy")
            }
            StrengthMeter(level: model.strength)
        }
        .padding(18)
        .lgkGroupSurface()
        .contentShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        .onTapGesture { model.copy() }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { model.copy() }
    }

    /// glowOrange reads well on the dark surface only; on the white surface it is under 2:1, so light mode
    /// uses the darker amber `warning` for symbols.
    private var symbolColor: Color { scheme == .dark ? Palette.glowOrange : Palette.warning }

    /// Digits in accent, symbols in orange, letters in the text colour.
    static func colored(_ value: String, symbol: Color) -> AttributedString {
        var out = AttributedString()
        for ch in value {
            var piece = AttributedString(String(ch))
            piece.foregroundColor = ch.isASCII && ch.isNumber ? Palette.accent
                : (ch.isLetter ? Palette.text : symbol)
            out += piece
        }
        return out
    }
}

/// Four segments and the strength's name. Danger, warning, accent, success.
struct StrengthMeter: View {
    let level: GeneratorStrength.Level

    var body: some View {
        HStack(spacing: 10) {
            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { i in
                    Capsule()
                        .fill(i < level.segments ? Self.color(level) : Palette.separator)
                        .frame(height: 6)
                }
            }
            Text(level.label)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(Palette.text)
                .fixedSize()
        }
        .animation(.snappy, value: level)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Strength: \(level.label)")
    }

    static func color(_ level: GeneratorStrength.Level) -> Color {
        switch level {
        case .weak: Palette.danger
        case .fair: Palette.warning
        case .strong: Palette.accent
        case .veryStrong: Palette.success
        }
    }
}

// MARK: mode

/// Password | Passphrase as a glass capsule; the selected side gets the accent pill (as the tab bar does).
struct GlassModePicker: View {
    @Binding var mode: GeneratorOptions.Mode
    @SwiftUI.Namespace private var pill

    var body: some View {
        HStack(spacing: 4) {
            segment(.password, String(localized: "Password"))
            segment(.passphrase, String(localized: "Passphrase"))
        }
        .padding(4)
        .frame(minHeight: 48)
        .lgkGlass(in: Capsule())
    }

    private func segment(_ m: GeneratorOptions.Mode, _ title: String) -> some View {
        let selected = mode == m
        return Button { withAnimation(.snappy) { mode = m } } label: {
            Text(title)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
                .padding(.horizontal, 14).padding(.vertical, 10)
                .frame(maxWidth: .infinity)
                .foregroundStyle(selected ? Palette.accentText : Palette.text)
                .background {
                    if selected {
                        Capsule().fill(Palette.accent.opacity(0.18)).matchedGeometryEffect(id: "pill", in: pill)
                    }
                }
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: options

/// The options for the current mode, as rows with SF Symbols on a solid card.
struct GeneratorOptionsCard: View {
    @Binding var options: GeneratorOptions

    static let sliderLengthRange = 8...64
    static let separators: [(String, String)] = [("-", String(localized: "Dash")), (" ", String(localized: "Space")), (".", String(localized: "Dot")), ("_", String(localized: "Underscore")), ("", String(localized: "None"))]

    var body: some View {
        VStack(spacing: 0) {
            if options.mode == .password {
                lengthRow
                divider
                toggle(String(localized: "Lowercase (a-z)"), "textformat.abc", $options.lowercase)
                divider
                toggle(String(localized: "Uppercase (A-Z)"), "textformat", $options.uppercase)
                divider
                toggle(String(localized: "Digits (0-9)"), "number", $options.digits)
                divider
                toggle(String(localized: "Symbols"), "asterisk", $options.symbols)
                divider
                toggle(String(localized: "Avoid look-alike characters"), "eye.slash", $options.avoidAmbiguous)
            } else {
                wordsRow
                divider
                separatorRow
                divider
                toggle(String(localized: "Capitalize words"), "textformat.size.larger", $options.capitalize)
                divider
                toggle(String(localized: "Add a number"), "number", $options.appendNumber)
            }
        }
        .padding(.vertical, 4)
        .lgkGroupSurface()
    }

    private var divider: some View { Rectangle().fill(Palette.separator).frame(height: 1).padding(.leading, 56) }

    private func icon(_ name: String) -> some View {
        Image(systemName: name)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(Palette.accentText)
            .frame(width: 30, height: 30)
            .background(Palette.innerTile, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .accessibilityHidden(true)
    }

    private func toggle(_ title: String, _ symbol: String, _ isOn: Binding<Bool>) -> some View {
        Toggle(isOn: isOn) {
            HStack(spacing: 12) { icon(symbol); Text(title).foregroundStyle(Palette.text) }
        }
        .tint(Palette.accent)
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    /// Slider 8–64 for the usual range; the stepper goes on to 256.
    private var lengthRow: some View {
        VStack(spacing: 8) {
            HStack(spacing: 12) {
                icon("ruler")
                Text("Length").foregroundStyle(Palette.text)
                Spacer()
                Text("\(options.length)")
                    .font(.body.monospacedDigit().weight(.semibold)).foregroundStyle(Palette.text)
                Stepper("Length", value: $options.length, in: PasswordGenerator.lengthRange)
                    .labelsHidden()
                    .accessibilityValue("\(options.length) characters")
            }
            Slider(value: Self.sliderBinding($options.length, in: Self.sliderLengthRange),
                   in: Double(Self.sliderLengthRange.lowerBound)...Double(Self.sliderLengthRange.upperBound), step: 1)
                .tint(Palette.accent)
                .accessibilityLabel("Length")
                .accessibilityValue("\(options.length) characters")
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private var wordsRow: some View {
        VStack(spacing: 8) {
            HStack(spacing: 12) {
                icon("text.word.spacing")
                Text("Words").foregroundStyle(Palette.text)
                Spacer()
                Text("\(options.words)")
                    .font(.body.monospacedDigit().weight(.semibold)).foregroundStyle(Palette.text)
            }
            Slider(value: Self.sliderBinding($options.words, in: PasswordGenerator.wordsRange),
                   in: Double(PasswordGenerator.wordsRange.lowerBound)...Double(PasswordGenerator.wordsRange.upperBound), step: 1)
                .tint(Palette.accent)
                .accessibilityLabel("Words")
                .accessibilityValue("\(options.words) words")
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private var separatorRow: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                icon("minus")
                Text("Separator").foregroundStyle(Palette.text)
            }
            // Wraps onto further lines instead of scrolling, so every chip is fully visible at any text size.
            ChipFlowLayout(spacing: 8) {
                ForEach(Self.separators, id: \.0) { sep, name in chip(sep, name) }
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }

    private func chip(_ sep: String, _ name: String) -> some View {
        let selected = options.separator == sep
        return Button { options.separator = sep } label: {
            Text(name)
                .font(.subheadline.weight(selected ? .semibold : .regular))
                .padding(.horizontal, 14).padding(.vertical, 8)
                .foregroundStyle(selected ? Palette.accentText : Palette.text)
                .background(selected ? Palette.accent.opacity(0.18) : Palette.innerTile, in: Capsule())
                .overlay { if selected { Capsule().strokeBorder(Palette.accent.opacity(0.5), lineWidth: 1) } }
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Separator: \(name)")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    /// An Int option as a slider value. Above the slider's range (a stepper length over 64) the thumb sits at
    /// the end and the value is kept until the slider is moved.
    static func sliderBinding(_ value: Binding<Int>, in range: ClosedRange<Int>) -> Binding<Double> {
        Binding(get: { Double(min(max(value.wrappedValue, range.lowerBound), range.upperBound)) },
                set: { new in
                    let n = Int(new.rounded())
                    if n != min(max(value.wrappedValue, range.lowerBound), range.upperBound) { value.wrappedValue = n }
                })
    }
}

extension View {
    /// The prominent toolbar action: Liquid Glass on iOS 26, a filled accent button before.
    @ViewBuilder
    func lgkProminentButton() -> some View {
        if #available(iOS 26, *) {
            buttonStyle(.glassProminent).tint(Palette.accent)
        } else {
            buttonStyle(.borderedProminent).tint(Palette.accent).foregroundStyle(Palette.onAccent)
        }
    }
}

/// Left-aligned rows that wrap: each subview at its ideal size, a new row when the next one would not fit.
struct ChipFlowLayout: Layout {
    var spacing: CGFloat = 8

    /// The origin of each item for `sizes` within `width`, and the total size. An item wider than `width` gets
    /// a row of its own (the chip's text then wraps inside it, see `sizeThatFits`).
    static func arrange(_ sizes: [CGSize], width: CGFloat, spacing: CGFloat) -> (origins: [CGPoint], size: CGSize) {
        var origins: [CGPoint] = []
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, widest: CGFloat = 0
        for size in sizes {
            if x > 0, x + size.width > width {
                x = 0; y += rowHeight + spacing; rowHeight = 0
            }
            origins.append(CGPoint(x: x, y: y))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            widest = max(widest, x - spacing)
        }
        return (origins, CGSize(width: widest, height: sizes.isEmpty ? 0 : y + rowHeight))
    }

    private func sizes(_ subviews: Subviews, width: CGFloat) -> [CGSize] {
        subviews.map { $0.sizeThatFits(ProposedViewSize(width: width.isFinite ? width : nil, height: nil)) }
            .map { CGSize(width: width.isFinite ? min($0.width, width) : $0.width, height: $0.height) }
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        let result = Self.arrange(sizes(subviews, width: width), width: width, spacing: spacing)
        return CGSize(width: width.isFinite ? width : result.size.width, height: result.size.height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let all = sizes(subviews, width: bounds.width)
        let origins = Self.arrange(all, width: bounds.width, spacing: spacing).origins
        for (i, subview) in subviews.enumerated() {
            subview.place(at: CGPoint(x: bounds.minX + origins[i].x, y: bounds.minY + origins[i].y),
                          proposal: ProposedViewSize(all[i]))
        }
    }
}
