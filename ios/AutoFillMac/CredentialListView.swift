import SwiftUI
import AppSharedMac

/// The site's passkeys (a passkey-capable page), the page's logins, then a search over every login. Picking a
/// row fills it or signs in with it.
struct CredentialListView: View {
    @Bindable var model: MacAutoFillModel

    var body: some View {
        if model.isTextInsertion { textBody } else { loginBody }
    }

    /// UX workstream 11: card and identity fields; nothing is pre-selected, the card number and security code
    /// are masked.
    private var textBody: some View {
        VStack(spacing: 12) {
            HStack {
                Text("Choose what to fill").font(.headline).foregroundStyle(Palette.text)
                Spacer()
                Button("Cancel", role: .cancel) { model.cancel() }.keyboardShortcut(.cancelAction)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    if model.textFields.isEmpty {
                        Text("No card or identity saved yet.").font(.callout).foregroundStyle(Palette.secondaryText)
                    }
                    ForEach(model.textFields) { f in
                        Button { model.selectText(f) } label: {
                            HStack {
                                Image(systemName: f.isCard ? "creditcard" : "person.text.rectangle")
                                    .foregroundStyle(Palette.accentText)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(f.label) · \(f.display)").foregroundStyle(Palette.text)
                                    Text(f.itemTitle).font(.caption).foregroundStyle(Palette.secondaryText)
                                }
                                Spacer()
                            }
                            .padding(.vertical, 6).padding(.horizontal, 8)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("\(f.label), \(f.itemTitle)")
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lgkGroupSurface(cornerRadius: 16)
            }
        }
        .padding(20)
        .frame(width: 420, height: 440)
    }

    private var loginBody: some View {
        VStack(spacing: 12) {
            HStack {
                Text(model.isOneTimeCode ? String(localized: "Choose a verification code") : String(localized: "Choose a login"))
                    .font(.headline).foregroundStyle(Palette.text)
                Spacer()
                Button("Cancel", role: .cancel) { model.cancel() }.keyboardShortcut(.cancelAction)
            }
            TextField("Search all logins", text: $model.query)
                .textFieldStyle(.plain).padding(.horizontal, 12).padding(.vertical, 8)
                .lgkGlass(in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    if model.query.trimmingCharacters(in: .whitespaces).isEmpty {
                        if !model.passkeys.isEmpty { passkeySection }
                        section(String(localized: "For this website"), rows: model.matches,
                                empty: String(localized: "No logins for this website. Search to choose another."))
                    } else {
                        section(String(localized: "All logins"), rows: model.searchResults, empty: String(localized: "No logins found."))
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .lgkGroupSurface(cornerRadius: 16)
            }
        }
        .padding(20)
        .frame(width: 420, height: 440)
    }

    @ViewBuilder
    private var passkeySection: some View {
        Text("Passkeys").font(.caption.weight(.semibold)).foregroundStyle(Palette.secondaryText)
        ForEach(model.passkeys, id: \.itemID) { p in
            Button { model.selectPasskey(p) } label: {
                HStack {
                    Image(systemName: "person.badge.key.fill").foregroundStyle(Palette.accentText)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(p.title.isEmpty ? p.rpID : p.title).foregroundStyle(Palette.text)
                        if !p.userName.isEmpty {
                            Text(p.userName).font(.caption).foregroundStyle(Palette.secondaryText)
                        }
                    }
                    Spacer()
                }
                .padding(.vertical, 6).padding(.horizontal, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }

    @ViewBuilder
    private func section(_ title: String, rows: [MacAutoFillRow], empty: String) -> some View {
        Text(title).font(.caption.weight(.semibold)).foregroundStyle(Palette.secondaryText)
        if rows.isEmpty {
            Text(empty).font(.callout).foregroundStyle(Palette.secondaryText).padding(.vertical, 8)
        }
        ForEach(rows) { row in
            Button { model.select(row) } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.login.title.isEmpty ? String(localized: "Untitled login") : row.login.title)
                            .foregroundStyle(Palette.text)
                        if !row.login.username.isEmpty {
                            Text(row.login.username).font(.caption).foregroundStyle(Palette.secondaryText)
                        }
                    }
                    Spacer()
                    if row.strict {
                        Image(systemName: "lock.shield").foregroundStyle(Palette.secondaryText)
                            .help("Needs your master password")
                    }
                }
                .padding(.vertical, 6).padding(.horizontal, 8)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
    }
}
