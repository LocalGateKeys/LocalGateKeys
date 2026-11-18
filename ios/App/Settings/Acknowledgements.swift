import SwiftUI
import AppShared

/// Third-party notices, read from the licence files bundled from ios/LGKCore (and its swift-crypto checkout) and
/// from yubikit-ios.
struct Acknowledgement: Identifiable, Sendable {
    let name: String
    let licence: String
    let text: String
    var id: String { name }

    static let all: [Acknowledgement] = [
        Acknowledgement(name: "swift-crypto", licence: "Apache-2.0",
                        text: [load("swift-crypto-NOTICE"), load("swift-crypto-LICENSE")].joined(separator: "\n\n")),
        Acknowledgement(name: "phc-winner-argon2", licence: "CC0-1.0", text: load("phc-winner-argon2-LICENSE")),
        // YubiKey over NFC for the app password (SwiftPM, exact version 4.7.0; iPhone app only).
        Acknowledgement(name: "yubikit-ios 4.7.0", licence: "Apache-2.0", text: load("yubikit-ios-LICENSE")),
        Acknowledgement(name: "2FA Directory (site data)", licence: "MIT, CC BY 4.0", text: siteDataNotice),
    ]

    /// Credit for the bundled site-features list (which sites offer two-factor codes and passkeys).
    static let siteDataNotice = """
        TOTP data: 2FA Directory (https://2fa.directory), by 2factorauth.
        Source: https://api.2fa.directory/v3/totp.json
        Licence: MIT, https://github.com/2factorauth/twofactorauth/blob/master/LICENSE.md
        Data reduced to registrable domains.

        MIT License

        Copyright (c) 2factorauth

        Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
        documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
        rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
        persons to whom the Software is furnished to do so, subject to the following conditions:

        The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
        Software.

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
        WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
        COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
        OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        Passkey data: Passkeys.2FA.Directory (https://passkeys.2fa.directory), by 2factorauth.
        Source: https://passkeys.2fa.directory
        Licence: Creative Commons Attribution 4.0 International (CC BY 4.0),
        https://creativecommons.org/licenses/by/4.0/ (data licence file:
        https://github.com/2factorauth/passkeys/blob/master/LICENSE.md)
        Changes: data reduced to registrable domains and the two flags (passkey, totp) per domain.
        """

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
