import SwiftUI
import AppSharedMac

/// The New item chooser (⌘N), in the Windows groups and order (`shell/new_item.py`), Website login first.
/// Kinds the Mac does not create yet (desktop logins, passkeys, documents) are left out. A number key picks
/// the matching kind; typing filters by name.
struct NewItemMenu: View {
    let onChoose: (EditorKind) -> Void
    let onClose: () -> Void
    /// "Scan QR code…": a 2FA setup code or an authenticator export, from an image (nil hides it).
    var onScan: (() -> Void)? = nil
    /// "Attach a file…": a document item from a file (nil hides it).
    var onAttachFile: (() -> Void)? = nil
    @State private var filter = ""
    @FocusState private var focused: Bool
    @Environment(\.macTheme) private var theme

    static let groups: [(String, [EditorKind])] = [
        (String(localized: "Sign-ins"), [.web]),
        (String(localized: "Money"), [.card, .bankAccount]),
        (String(localized: "Personal"), [.identity, .note]),
        (String(localized: "Tech"), [.sshKey, .apiKey, .wifi, .bookmark]),
        (String(localized: "Things you own"), [.license, .subscription, .warranty, .purchase]),
    ]

    static var flat: [EditorKind] { groups.flatMap(\.1) }

    static func label(_ kind: EditorKind) -> String {
        switch kind {
        case .web: String(localized: "Website login")
        case .card: String(localized: "Payment card")
        case .bankAccount: String(localized: "Bank account")
        case .identity: String(localized: "Identity")
        case .note: String(localized: "Secure note")
        case .sshKey: String(localized: "SSH key")
        case .apiKey: String(localized: "API key")
        case .wifi: String(localized: "Wi-Fi network")
        case .bookmark: String(localized: "Bookmark")
        case .license: String(localized: "Software licence")
        case .subscription: String(localized: "Subscription")
        case .warranty: String(localized: "Warranty")
        case .purchase: String(localized: "Purchase")
        }
    }

    private var visible: [EditorKind]? {
        filter.isEmpty ? nil : Self.flat.filter { Self.label($0).localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("New item").font(.system(size: 18, weight: .semibold)).foregroundStyle(theme.text)
            Text(filter.isEmpty ? String(localized: "Press a number key, or start typing a name.")
                 : String(localized: "Showing kinds matching \u{201C}\(filter)\u{201D}. Delete to clear, Esc to close."))
                .font(.system(size: 13)).foregroundStyle(theme.textMuted).padding(.top, 4).padding(.bottom, 4)
            if let onScan, filter.isEmpty {
                Button(action: onScan) {
                    HStack(spacing: 8) {
                        Image(systemName: "qrcode.viewfinder").foregroundStyle(theme.accent)
                        Text("Scan QR code…").foregroundStyle(theme.text)
                        Text("2FA setup code or authenticator export").foregroundStyle(theme.textFaint)
                        Spacer(minLength: 0)
                    }
                    .font(.system(size: 14))
                    .padding(.horizontal, 12).padding(.vertical, 10)
                    .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous).strokeBorder(theme.glassBorder))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.top, 8)
            }
            if let onAttachFile, filter.isEmpty {
                Button(action: onAttachFile) {
                    HStack(spacing: 8) {
                        Image(systemName: "paperclip").foregroundStyle(theme.accent)
                        Text("Attach a file…").foregroundStyle(theme.text)
                        Text("Stored encrypted, up to 25 MB").foregroundStyle(theme.textFaint)
                        Spacer(minLength: 0)
                    }
                    .font(.system(size: 14))
                    .padding(.horizontal, 12).padding(.vertical, 10)
                    .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous).strokeBorder(theme.glassBorder))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.top, 8)
            }
            if let visible {
                grid(visible)
                if visible.isEmpty { Text("No kind matches.").foregroundStyle(theme.textMuted).padding(.top, 8) }
            } else {
                ForEach(Self.groups, id: \.0) { name, kinds in
                    Text(name).font(.system(size: 12)).foregroundStyle(theme.textFaint).padding(.top, 12).padding(.bottom, 6)
                    grid(kinds)
                }
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 18)
        .frame(width: 600, alignment: .leading)
        .background(WashBackground())
        .focusable()
        .focusEffectDisabled()
        .focused($focused)
        .onAppear { focused = true }
        .onExitCommand(perform: onClose)
        .onKeyPress(phases: .down) { press in key(press) }
    }

    private func grid(_ kinds: [EditorKind]) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 140), spacing: 6)], alignment: .leading, spacing: 6) {
            ForEach(kinds) { kind in
                Button { onChoose(kind) } label: {
                    HStack(spacing: 8) {
                        if filter.isEmpty, let n = Self.flat.firstIndex(of: kind), n < 9 {
                            Text("\(n + 1)").font(.system(size: 11).monospacedDigit()).foregroundStyle(theme.textFaint)
                        }
                        Text(Self.label(kind)).foregroundStyle(theme.text)
                        Spacer(minLength: 0)
                    }
                    .font(.system(size: 14))
                    .padding(.horizontal, 12).padding(.vertical, 10)
                    .background(theme.group, in: RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusField, style: .continuous).strokeBorder(theme.glassBorder))
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func key(_ press: KeyPress) -> KeyPress.Result {
        if press.key == .escape { onClose(); return .handled }
        if press.key == .delete { if !filter.isEmpty { filter.removeLast() }; return .handled }
        guard press.modifiers.subtracting(.shift).isEmpty, let c = press.characters.first, !c.isWhitespace else { return .ignored }
        if filter.isEmpty, let n = c.wholeNumberValue, (1...9).contains(n), n <= Self.flat.count {
            onChoose(Self.flat[n - 1]); return .handled
        }
        if c.isLetter || c.isNumber || c == "-" { filter.append(c); return .handled }
        return .ignored
    }
}
