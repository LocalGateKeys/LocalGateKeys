import SwiftUI
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// Which detail fields are note text: a login's `notes`, and the `body` of a secure note. Nothing else is formatted.
/// The per-device "Show formatting" switch sits under the note on the detail screen (default on).
enum NoteFormatting {
    static let settingKey = "notes.showFormatting"

    static func formats(kind: String, fieldId: String) -> Bool {
        fieldId == "notes" || (kind == "note" && fieldId == "body")
    }
}

/// The colours a note is drawn in (the iPhone uses `Palette`, the Mac its own theme).
struct MarkdownNoteColors {
    let text: Color
    let secondary: Color
    let accent: Color
    /// Behind code, and the horizontal rule.
    let codeBackground: Color
}

/// A note with the Markdown subset applied (display only): headings, bold, italic, code, lists and rules. Links are
/// never clickable (they read "text (url)") and checklist boxes are not tappable.
struct MarkdownNoteView: View {
    private let blocks: [MDNode]
    private let colors: MarkdownNoteColors
    private let selectable: Bool

    init(text: String, colors: MarkdownNoteColors, selectable: Bool) {
        blocks = NoteMarkdown.parse(text)
        self.colors = colors
        self.selectable = selectable
    }

    var body: some View {
        if selectable {
            content.textSelection(.enabled)
        } else {
            content.textSelection(.disabled)
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(blocks.enumerated()), id: \.offset) { _, block in
                blockView(block)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private func blockView(_ block: MDNode) -> some View {
        switch block {
        case .heading(let level, let inline):
            Text(Self.attributed(inline, colors: colors))
                .font(Self.headingFont(level))
                .foregroundStyle(colors.text)
        case .paragraph(let inline):
            Text(Self.attributed(inline, colors: colors)).foregroundStyle(colors.text)
        case .bullets(let items):
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                listLine(marker: "\u{2022}", spoken: nil, inline: item)
            }
        case .numbered(let items):
            ForEach(Array(items.enumerated()), id: \.offset) { index, item in
                listLine(marker: "\(index + 1).", spoken: nil, inline: item)
            }
        case .todos(let items):
            ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                listLine(marker: item.done ? "\u{2611}" : "\u{2610}",
                         spoken: item.done ? String(localized: "Item done") : String(localized: "Item not done"),
                         inline: item.content)
            }
        case .codeBlock(let code):
            Text(verbatim: code)
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(colors.text)
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(colors.codeBackground, in: RoundedRectangle(cornerRadius: 8))
        case .rule:
            Rectangle().fill(colors.codeBackground).frame(height: 1).padding(.vertical, 4)
        }
    }

    private static func headingFont(_ level: Int) -> Font {
        switch level {
        case 1: return Font.title2.bold()
        case 2: return Font.title3.bold()
        default: return Font.headline
        }
    }

    private func listLine(marker: String, spoken: String?, inline: [MDInline]) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(verbatim: marker)
                .foregroundStyle(colors.secondary)
                .accessibilityLabel(spoken ?? marker)
            Text(Self.attributed(inline, colors: colors)).foregroundStyle(colors.text)
        }
        .accessibilityElement(children: .combine)
    }

    /// Inline nodes as one styled string, built node by node (never `AttributedString(markdown:)`, whose grammar
    /// differs from the vectors). A link is plain text "text (url)" in the accent colour: no click target.
    static func attributed(_ nodes: [MDInline], colors: MarkdownNoteColors, intent: InlinePresentationIntent = []) -> AttributedString {
        var result = AttributedString()
        for node in nodes {
            switch node {
            case .text(let v):
                result.append(run(v, intent: intent, colors: colors, link: false))
            case .bold(let inner):
                result.append(attributed(inner, colors: colors, intent: intent.union(.stronglyEmphasized)))
            case .italic(let inner):
                result.append(attributed(inner, colors: colors, intent: intent.union(.emphasized)))
            case .code(let v):
                var part = run(v, intent: intent.union(.code), colors: colors, link: false)
                part.backgroundColor = colors.codeBackground
                result.append(part)
            case .link(let text, let url):
                result.append(run("\(text) (\(url))", intent: intent, colors: colors, link: true))
            }
        }
        return result
    }

    private static func run(_ s: String, intent: InlinePresentationIntent, colors: MarkdownNoteColors, link: Bool) -> AttributedString {
        var part = AttributedString(s)
        if !intent.isEmpty { part.inlinePresentationIntent = intent }
        if link {
            part.foregroundColor = colors.accent
            part.underlineStyle = Text.LineStyle.single
        }
        return part
    }
}

/// The small "Show formatting" switch under a note.
struct ShowFormattingToggle: View {
    @Binding var isOn: Bool

    var body: some View {
        Toggle("Show formatting", isOn: $isOn).font(.footnote)
    }
}
