import SwiftUI
import AppShared

/// Third-party notices, read from the licence files bundled from ios/LGKCore (and its swift-crypto checkout).
struct Acknowledgement: Identifiable, Sendable {
    let name: String
    let licence: String
    let text: String
    var id: String { name }

    static let all: [Acknowledgement] = [
        Acknowledgement(name: "swift-crypto", licence: "Apache-2.0",
                        text: [load("swift-crypto-NOTICE"), load("swift-crypto-LICENSE")].joined(separator: "\n\n")),
        Acknowledgement(name: "phc-winner-argon2", licence: "CC0-1.0", text: load("phc-winner-argon2-LICENSE")),
    ]

    private static func load(_ name: String) -> String {
        let url = Bundle(for: BundleToken.self).url(forResource: name, withExtension: "txt")
            ?? Bundle.main.url(forResource: name, withExtension: "txt")
        return url.flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
    }
}

private final class BundleToken {}

struct AcknowledgementsView: View {
    var body: some View {
        List {
            ForEach(Acknowledgement.all) { ack in
                NavigationLink {
                    ScrollView {
                        // Verbatim: the licence's URLs stay plain text, never links.
                        Text(verbatim: ack.text).font(.footnote.monospaced()).foregroundStyle(Palette.text)
                            .textSelection(.enabled).padding(16)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Palette.groupSurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                            .padding(16)
                    }
                    .lgkAuroraBackground()
                    .navigationTitle(ack.name)
                    .navigationBarTitleDisplayMode(.inline)
                } label: {
                    LabeledContent(ack.name, value: ack.licence)
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .lgkAuroraBackground()
        .navigationTitle("Acknowledgements")
        .navigationBarTitleDisplayMode(.inline)
    }
}

extension Appearance {
    /// For `preferredColorScheme` on the app root; nil follows the system.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
