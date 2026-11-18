import SwiftUI
import WidgetKit
import AppShared

/// Sub-plan 06: the 2FA codes pinned in the app, on the Lock Screen (rectangular and inline) and the Home Screen
/// (small and medium), at most `PinnedCodeStore.maxShown`. Codes are marked privacy-sensitive, so the system
/// redacts them while the iPhone is locked; a tap opens the app at its Codes row.
@main
struct CodesWidget: Widget {
    static let kind = "app.localgatekeys.codes"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: CodesTimelineProvider()) { entry in
            CodesWidgetView(entry: entry)
        }
        .configurationDisplayName("Pinned codes")
        .description("Your pinned two-factor codes.")
        .supportedFamilies([.accessoryRectangular, .accessoryInline, .systemSmall, .systemMedium])
    }
}

struct CodesWidgetView: View {
    let entry: CodesEntry
    /// Tests render a family directly (WidgetKit's environment value cannot be set outside a widget).
    var familyOverride: WidgetFamily? = nil
    @Environment(\.widgetFamily) private var environmentFamily
    private var family: WidgetFamily { familyOverride ?? environmentFamily }

    var body: some View {
        content
            .widgetURL(CodesTimeline.openURL)
            .containerBackground(for: .widget) {
                if isAccessory { Color.clear } else { Rectangle().fill(.background) }
            }
    }

    private var isAccessory: Bool { family == .accessoryInline || family == .accessoryRectangular }

    @ViewBuilder private var content: some View {
        switch entry.content {
        case .codes(let codes):
            codesView(codes)
        case .empty:
            message("Pin a code in LocalGateKeys", systemImage: "pin")
        case .phoneLocked:
            message(DeviceText.isPad ? "ipad.widget.unlockToSeeCodes" : "Unlock iPhone to see codes", systemImage: "lock")
        case .openApp:
            message("Open LocalGateKeys to show codes", systemImage: "arrow.up.forward.app")
        }
    }

    @ViewBuilder private func codesView(_ codes: [CodesWidgetEntry.Code]) -> some View {
        switch family {
        case .accessoryInline:
            if let first = codes.first {
                // The code first, so a long title is what gets cut.
                Text(verbatim: Self.grouped(first.code) + " " + first.title)
                    .privacySensitive()
                    .accessibilityLabel(Text(verbatim: Self.spoken(first.code) + ", " + first.title))
            }
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 1) {
                ForEach(0..<min(3, codes.count), id: \.self) { i in
                    HStack(spacing: 6) {
                        Text(codes[i].title).font(.caption).lineLimit(1).privacySensitive()
                        Spacer(minLength: 4)
                        codeText(codes[i].code, font: .headline)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        case .systemSmall:
            VStack(alignment: .leading, spacing: 10) {
                ForEach(0..<min(2, codes.count), id: \.self) { i in block(codes[i], font: .title2) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        default:
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)],
                      alignment: .leading, spacing: 12) {
                ForEach(0..<min(PinnedCodeStore.maxShown, codes.count), id: \.self) { i in block(codes[i], font: .title3) }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    private func block(_ code: CodesWidgetEntry.Code, font: Font) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(code.title).font(.caption).foregroundStyle(.secondary).lineLimit(1).privacySensitive()
            codeText(code.code, font: font)
        }
    }

    private func codeText(_ code: String, font: Font) -> some View {
        Text(verbatim: Self.grouped(code))
            .font(font.monospacedDigit().weight(.semibold))
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .privacySensitive()
            .accessibilityLabel(Text(verbatim: Self.spoken(code)))
    }

    @ViewBuilder private func message(_ text: LocalizedStringKey, systemImage: String) -> some View {
        switch family {
        case .accessoryInline:
            Label(text, systemImage: systemImage)
        default:
            VStack(alignment: .leading, spacing: 4) {
                Image(systemName: systemImage)
                    .font(isAccessory ? .body : .title3)
                    .widgetAccentable()
                Text(text)
                    .font(isAccessory ? .caption : .subheadline)
                    .minimumScaleFactor(0.8)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        }
    }

    /// "123456" as "123 456" (and "1234 5678"), for reading at a glance.
    static func grouped(_ code: String) -> String {
        guard code.count > 4 else { return code }
        let cut = code.index(code.startIndex, offsetBy: code.count / 2)
        return String(code[..<cut]) + " " + String(code[cut...])
    }

    /// The digits one by one for VoiceOver ("1 2 3 4 5 6", not "one hundred twenty-three thousand").
    static func spoken(_ code: String) -> String {
        code.map { String($0) }.joined(separator: " ")
    }
}
