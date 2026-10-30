import SwiftUI
import AppShared

/// The Security tab: a score ring, then Breached, Reused, Weak, Old and 2FA available, each opening its list.
struct SecurityCheckView: View {
    @State var model: SecurityCheckModel
    let store: any ItemStore
    let pro: ProModel
    let onChange: () -> Void
    /// Expiry reminders: the Upcoming section (UX plan workstream 10).
    @Environment(\.phoneReminders) private var reminders
    @Bindable private var settings: AppSettings = .shared
    @State private var confirmBreachCheck = false

    var body: some View {
        List {
            Section { scoreHeader }.listRowBackground(Color.clear).listRowInsets(EdgeInsets())
            Section {
                ForEach(SecurityCategory.allCases) { category in
                    NavigationLink(value: category) {
                        HStack(spacing: 12) {
                            Image(systemName: category.icon).frame(width: 28)
                                .foregroundStyle(tint(category)).accessibilityHidden(true)
                            Text(category.label).foregroundStyle(Palette.text)
                            Spacer()
                            Text("\(model.count(category))").foregroundStyle(Palette.secondaryText).monospacedDigit()
                        }
                    }
                    .accessibilityLabel("\(category.label), \(model.count(category)) items")
                }
            } header: {
                Text("Checks")
            } footer: {
                Text("Local checks are guidance, not a guarantee. Nothing leaves this iPhone unless you start a breach check.")
            }
            .listRowBackground(Palette.groupSurface)
            breachSection
            if let reminders { UpcomingRemindersSection(reminders: reminders) }
        }
        .scrollContentBackground(.hidden)
        .safeAreaPadding(.bottom, SettingsView.legacyTabBarRoom)
        .lgkAuroraBackground()
        .navigationTitle("Security")
        .navigationDestination(for: SecurityCategory.self) { category in
            SecurityIssueList(model: model, category: category, store: store, pro: pro, onChange: changed)
        }
        .navigationDestination(for: VaultItem.self) { ItemDetailView(item: $0, store: store, pro: pro, onChange: changed) }
        .onAppear { model.refresh() }
        .refreshable { model.refresh() }
        .alert("Check every password with Have I Been Pwned?", isPresented: $confirmBreachCheck) {
            Button("Check") { model.checkBreaches() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(SecurityCheckModel.consentText)
        }
    }

    private func changed() { model.refresh(); onChange() }

    private func tint(_ c: SecurityCategory) -> Color {
        model.count(c) == 0 ? Palette.success : (c == .breached || c == .weak ? Palette.danger : Palette.warning)
    }

    private var scoreHeader: some View {
        VStack(spacing: 8) {
            ScoreRing(score: model.score)
            Text(model.score == nil ? String(localized: "Add logins to see how healthy your passwords are.") : model.label)
                .font(.headline).foregroundStyle(Palette.text).multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .accessibilityElement(children: .combine)
    }

    private var breachSection: some View {
        Section {
            if let blocked = model.breachBlockedText {
                Text(blocked).font(.footnote).foregroundStyle(Palette.secondaryText)
            } else if model.running {
                HStack {
                    ProgressView()
                    Text(model.statusText ?? String(localized: "Checking…")).foregroundStyle(Palette.secondaryText)
                    Spacer()
                    Button("Cancel") { model.cancelBreachCheck() }
                }
            } else {
                Button("Check for breached passwords") { confirmBreachCheck = true }.foregroundStyle(Palette.accentText)
            }
            if !model.running, let status = model.statusText, model.breachBlockedText == nil {
                Text(status).font(.footnote).foregroundStyle(Palette.secondaryText)
            }
            if !model.dismissed.isEmpty {
                Button("Show dismissed items again") { model.restoreDismissed() }.foregroundStyle(Palette.accentText)
            }
        } header: {
            Text("Breach check")
        }
        .listRowBackground(Palette.groupSurface)
    }
}

/// The score, 0–100, as a ring.
struct ScoreRing: View {
    let score: Int?
    var body: some View {
        let value = Double(score ?? 0) / 100
        ZStack {
            Circle().stroke(Palette.separator, lineWidth: 12)
            Circle().trim(from: 0, to: value)
                .stroke(color, style: StrokeStyle(lineWidth: 12, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text(score.map(String.init) ?? "—").font(.largeTitle.bold().monospacedDigit()).foregroundStyle(Palette.text)
        }
        .frame(width: 120, height: 120)
        .accessibilityElement()
        .accessibilityLabel(score.map { String(localized: "Security score \($0) out of 100") } ?? String(localized: "No security score yet"))
    }

    private var color: Color {
        guard let score else { return Palette.separator }
        return score >= 80 ? Palette.success : (score >= 50 ? Palette.warning : Palette.danger)
    }
}

/// One check's logins, each with Change password (opens the site and the editor) and Dismiss for this item.
struct SecurityIssueList: View {
    let model: SecurityCheckModel
    let category: SecurityCategory
    let store: any ItemStore
    let pro: ProModel
    let onChange: () -> Void
    @State private var editingItem: VaultItem?
    @Environment(\.openURL) private var openURL

    var body: some View {
        List {
            Section {
                let rows = model.items(category)
                if rows.isEmpty {
                    Text("Nothing to fix here.").foregroundStyle(Palette.secondaryText)
                }
                ForEach(rows) { item in
                    // Swipe or long-press for the actions (also VoiceOver actions on the row).
                    NavigationLink(value: item) { VaultRow(item: item) }
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button("Dismiss") { model.dismiss(category, id: item.id) }.tint(Palette.secondaryText)
                            if category != .noTwoFactor {
                                Button("Change password") { changePassword(item) }.tint(Palette.accent)
                            }
                        }
                        .contextMenu {
                            if category != .noTwoFactor {
                                Button { changePassword(item) } label: { Label("Change password", systemImage: "key") }
                            }
                            Button { model.dismiss(category, id: item.id) } label: {
                                Label("Dismiss for this item", systemImage: "eye.slash")
                            }
                        }
                }
            } footer: {
                Text(String(localized: "\(category.explanation) Swipe left on a login to change its password or dismiss it here."))
            }
            .listRowBackground(Palette.groupSurface)
        }
        .scrollContentBackground(.hidden)
        .safeAreaPadding(.bottom, SettingsView.legacyTabBarRoom)
        .lgkAuroraBackground()
        .navigationTitle(category.label)
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $editingItem) { item in
            EditorView(model: EditorModel(store: store, pro: pro, editing: item, kind: EditorKind(kind: item.kind) ?? .web,
                                          clock: SystemClock(), random: SystemRandomSource(),
                                          keepsPasswordHistory: true),
                       pro: pro) { result in if result == .saved { onChange() } }
        }
    }

    /// Opens the site in Safari (when the login has one) and the editor, so the new password can be saved.
    private func changePassword(_ item: VaultItem) {
        if let url = item.openableURL { openURL(url) }
        if EditorKind(kind: item.kind) != nil { editingItem = item }
    }
}
