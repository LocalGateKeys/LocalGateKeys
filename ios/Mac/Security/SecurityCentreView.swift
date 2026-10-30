import SwiftUI
import LGKCore
import AppSharedMac

/// The sidebar's Security centre (Windows `SecurityPage.svelte` + `HealthPage.svelte`): score and headline,
/// issues to fix, the filtered logins with the explicit HIBP checks, then the panels and footnote.
struct SecurityCentreView: View {
    @Bindable var model: SecurityModel
    let overview: OverviewModel
    let items: [VaultItem]
    let gate: StrictItemGate
    let touchIDAvailable: Bool
    let onSettings: () -> Void
    var onImportExport: () -> Void = {}
    /// The Recovery centre's status (Backups panel, Recovery phrase row).
    var backup: RecoveryStatus?
    var onRecoveryCentre: (RecoveryCentreModel.Initial?) -> Void = { _ in }
    @Environment(\.macTheme) private var theme
    @State private var selectedID: String?

    private var logins: [VaultItem] {
        items.filter(\.isLogin).sorted { ($0.title.lowercased(), $0.id) < ($1.title.lowercased(), $1.id) }
    }

    private var titles: [String: String] {
        Dictionary(logins.map { ($0.id, $0.title.isEmpty ? $0.kindLabel : $0.title) }, uniquingKeysWith: { a, _ in a })
    }

    var body: some View {
        let health = overview.health
        let issues = SecurityModel.issues(health, titles: titles)
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header(health, issues: issues)
                if !issues.isEmpty { section(String(localized: "Issues to fix")) { issueRows(issues) } }
                panels
                section(String(localized: "Passwords")) { passwords(health) }
                Text(SecurityModel.footnote).font(.system(size: 11)).foregroundStyle(theme.textFaint)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(18).padding(.bottom, 24)
            .frame(maxWidth: 820, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .foregroundStyle(theme.text)
        .alert(model.confirmation?.title ?? "", isPresented: Binding(get: { model.confirmation != nil },
                                                                     set: { if !$0 { model.cancelConfirmation() } })) {
            Button("Check") { model.confirm() }
            Button("Cancel", role: .cancel) { model.cancelConfirmation() }
        } message: { Text(model.confirmation?.text ?? "") }
        .alert("Breach check", isPresented: Binding(get: { model.refusal != nil }, set: { if !$0 { model.refusal = nil } })) {
            if model.refusal?.0 == .disabled {
                Button(SecurityModel.turnOnAndCheck) { model.turnOnAndCheck() }
            }
            if model.refusal?.0 == .strictOffline {
                Button("Open Settings") { model.refusal = nil; onSettings() }
            }
            Button("Cancel", role: .cancel) { model.refusal = nil }
        } message: { Text(model.refusal?.0.text ?? "") }
    }

    // MARK: header

    private func header(_ health: VaultHealth?, issues: [SecurityIssue]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Security centre").font(.system(size: 19, weight: .semibold))
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                if let score = health?.score {
                    Text("\(score)").font(.system(size: 34, weight: .semibold))
                    Text("/ 100 · \(health?.label ?? "")").font(.system(size: 13)).foregroundStyle(theme.textMuted)
                }
            }
            Text(SecurityModel.headline(health, issues: issues)).font(.system(size: 14))
            Text(SecurityModel.subtitle).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func colour(_ tone: SecurityTone) -> Color {
        switch tone {
        case .neutral: theme.textMuted
        case .accent: theme.accent
        case .success: theme.success
        case .warning: theme.warning
        case .danger: theme.danger
        }
    }

    private func issueRows(_ issues: [SecurityIssue]) -> some View {
        ForEach(Array(issues.enumerated()), id: \.element.id) { index, issue in
            if index > 0 { divider }
            HStack(spacing: 12) {
                Text("\(issue.count)").font(.system(size: 17, weight: .semibold)).foregroundStyle(colour(issue.tone))
                    .frame(minWidth: 28)
                VStack(alignment: .leading, spacing: 2) {
                    Text(issue.title).font(.system(size: 13, weight: .medium))
                    Text(issue.description).font(.system(size: 11.5)).foregroundStyle(theme.textMuted).lineLimit(2)
                }
                Spacer(minLength: 12)
                Button(issue.actionLabel) { model.filter = issue.filter }
                    .buttonStyle(PillButtonStyle(primary: issue.tone == .danger))
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
        }
    }

    // MARK: passwords

    @ViewBuilder private func passwords(_ health: VaultHealth?) -> some View {
        let all = logins
        let wanted = SecurityModel.ids(model.filter, health: health, all: all.map(\.id))
        let shown = all.filter { wanted.contains($0.id) }
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                ForEach(SecurityFilter.allCases) { f in
                    let selected = model.filter == f
                    Button(f.label) { model.filter = f }
                        .buttonStyle(.plain).font(.system(size: 12))
                        .padding(.horizontal, 10).padding(.vertical, 4)
                        .foregroundStyle(selected ? theme.onAccent : theme.text)
                        .background(selected ? theme.accent : theme.chip, in: Capsule())
                }
            }
            HStack(spacing: 8) {
                Button("Check this password") { checkSelected() }
                    .buttonStyle(PillButtonStyle(primary: false))
                    .disabled(model.running || selectedLogin == nil)
                Button("Check all passwords") {
                    model.requestCheckAll(OverviewModel.healthLogins(all))
                }
                .buttonStyle(PillButtonStyle(primary: true)).disabled(model.running)
                if model.running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { model.cancelScan() }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
            if let status = model.statusText {
                Text(status).font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
            VStack(spacing: 0) {
                if shown.isEmpty {
                    Text(all.isEmpty ? String(localized: "No logins yet") : String(localized: "Nothing here")).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 8)
                }
                ForEach(shown) { item in loginRow(item, health: health) }
            }
            Text(SecurityModel.footer).font(.system(size: 11)).foregroundStyle(theme.textFaint)
        }
        .padding(14)
    }

    private var selectedLogin: VaultItem? { logins.first { $0.id == selectedID } }

    private func loginRow(_ item: VaultItem, health: VaultHealth?) -> some View {
        let tags = [health?.breached.contains(item.id) == true ? String(localized: "Breached") : nil,
                    health?.weak.contains(item.id) == true ? String(localized: "Weak") : nil,
                    health?.reused.contains(item.id) == true ? String(localized: "Reused") : nil,
                    health?.noTwoFactor.contains(item.id) == true ? String(localized: "No 2FA") : nil,
                    health?.old.contains(item.id) == true ? String(localized: "Old") : nil].compactMap { $0 }
        let selected = selectedID == item.id
        return HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(item.title.isEmpty ? item.kindLabel : item.title).font(.system(size: 13)).lineLimit(1)
                if let line = model.exposure[item.id] {
                    Text(line).font(.system(size: 11))
                        .foregroundStyle(model.exposureFound.contains(item.id) ? theme.danger : theme.textMuted)
                } else if !item.username.isEmpty {
                    Text(item.username).font(.system(size: 11)).foregroundStyle(theme.textMuted).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            ForEach(tags, id: \.self) { Pill(text: $0, colour: $0 == String(localized: "Breached") ? theme.danger : nil) }
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
        .background(selected ? theme.selection : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture { selectedID = item.id }
    }

    private func checkSelected() {
        guard let item = selectedLogin, let login = OverviewModel.healthLogins([item]).first else { return }
        gate.release(item, action: String(localized: "Check password")) { model.requestCheckOne(login) }
    }

    // MARK: panels

    private var panels: some View {
        let list = model.panels(touchIDAvailable: touchIDAvailable, backup: backup)
        return Grid(alignment: .topLeading, horizontalSpacing: 12, verticalSpacing: 12) {
            ForEach(0..<(list.count + 1) / 2, id: \.self) { r in
                GridRow {
                    ForEach(list[(r * 2)..<min(r * 2 + 2, list.count)]) { panel in
                        section(panel.title) {
                            ForEach(Array(panel.rows.enumerated()), id: \.element.id) { i, row in
                                if i > 0 { divider }
                                panelRow(row)
                            }
                        }
                    }
                }
            }
        }
    }

    private func panelRow(_ row: SecurityPanelRow) -> some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(row.label).font(.system(size: 13))
                Text(row.meta).font(.system(size: 11)).foregroundStyle(row.tone == .neutral ? theme.textMuted : colour(row.tone))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            if let label = row.buttonLabel {
                Button(label) {
                    switch row.action {
                    case .settings: onSettings()
                    case .toggleBreachChecks: model.settings.breachCheckEnabled.toggle()
                    case .toggleStrictOffline: model.settings.strictOfflineMode.toggle()
                    case .importExport: onImportExport()
                    case .recoveryCentre(let initial): onRecoveryCentre(initial)
                    case .later: break
                    }
                }
                .buttonStyle(PillButtonStyle(primary: false))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
    }

    // MARK: chrome

    private var divider: some View { Rectangle().fill(theme.panelBorder).frame(height: 1).padding(.leading, 14) }

    private func section<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title.uppercased()).font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.textFaint)
                .padding(.leading, 4)
            VStack(alignment: .leading, spacing: 0) { content() }
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
        }
    }
}
