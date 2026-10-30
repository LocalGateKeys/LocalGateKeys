import SwiftUI
import AppSharedMac

/// The sidebar's Import & export page (Windows Import / Export and Restore phone backup, the iPhone's
/// Import & Export): Import, Apple Passwords (macOS 26), Restore a phone backup, then Export. Files come
/// through the open and save panels; the review, the password and the column steps open as sheets.
struct ImportExportPage: View {
    @Bindable var model: ImportExportModel
    @State private var askingBackupPassword = false
    /// What to ask next once the sheet on screen has closed (the master password prompt is a window sheet).
    @State private var afterDismiss: AfterDismiss?

    enum AfterDismiss { case csv, encrypted(password: String, confirmation: String) }
    @Environment(\.macTheme) private var theme

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(ImportExportModel.title).font(.system(size: 19, weight: .semibold))
                Text(ImportExportModel.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let message = model.message { note(message, theme.text) }
                importCard
                if model.showsApplePasswords { applePasswordsCard }
                restoreCard
                exportCard
            }
            .foregroundStyle(theme.text)
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        // One sheet for every step, so the password or column step turns into the review in place.
        .sheet(item: Binding(get: { PageSheet.current(model) }, set: { if $0 == nil { model.reset() } })) { sheet in
            Group {
                switch sheet {
                case .review(let review): ImportReviewSheet(model: model, review: review)
                case .restore(let preview): ImportReviewSheet(model: model, restore: preview)
                case .password(let request): FilePasswordSheet(model: model, request: request)
                case .mapping(let request): GenericMappingSheet(model: model, request: request)
                }
            }
            .macThemed()
        }
        .sheet(isPresented: $askingBackupPassword, onDismiss: runAfterDismiss) {
            BackupPasswordSheet(model: model, onAccept: { p, c in
                afterDismiss = .encrypted(password: p, confirmation: c)
                askingBackupPassword = false
            }, onClose: { askingBackupPassword = false }).macThemed()
        }
        .sheet(isPresented: $model.confirmingCSV, onDismiss: runAfterDismiss) {
            CSVWarningSheet(onExport: { afterDismiss = .csv; model.confirmingCSV = false },
                            onCancel: { model.confirmingCSV = false }).macThemed()
        }
    }

    /// Runs when the warning or password sheet has fully closed, so the next prompt is never dropped.
    private func runAfterDismiss() {
        guard let next = afterDismiss else { return }
        afterDismiss = nil
        switch next {
        case .csv:
            model.acceptCSVWarning(choose: { MacFilePanels.chooseExport(name: ImportExportModel.exportFileName(csv: true), csv: true) })
        case .encrypted(let p, let c):
            // Refused while another prompt is open: the model says so in `exportMessage`, shown on the Export card.
            _ = model.requestEncryptedExport(password: p, confirmation: c, choose: {
                MacFilePanels.chooseExport(name: ImportExportModel.exportFileName(csv: false), csv: false)
            })
        }
    }

    // MARK: cards

    private var importCard: some View {
        card(String(localized: "Import")) {
            Text(ImportExportModel.importHelp).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(model.busy ? String(localized: "Reading…") : String(localized: "Choose a file…")) {
                    guard let url = MacFilePanels.chooseImport() else { return }
                    Task { await model.importFile(url: url) }
                }
                .buttonStyle(PillButtonStyle(primary: true)).disabled(model.busy)
                Spacer()
            }
        }
    }

    private var applePasswordsCard: some View {
        card(String(localized: "Apple Passwords")) {
            Text(ImportExportModel.applePasswordsHelp).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if model.pendingExchangeToken != nil {
                Button("Review the passwords from Apple Passwords") { Task { await model.importFromApplePasswords() } }
                    .buttonStyle(PillButtonStyle(primary: true)).disabled(model.busy)
            }
        }
    }

    private var restoreCard: some View {
        card(String(localized: "Restore a phone backup")) {
            Text(ImportExportModel.restoreHelp).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Choose a backup…") {
                    guard let url = MacFilePanels.chooseBackup() else { return }
                    Task { await model.importFile(url: url) }
                }
                .buttonStyle(PillButtonStyle(primary: false)).disabled(model.busy)
                Spacer()
            }
        }
    }

    private var exportCard: some View {
        card(String(localized: "Export")) {
            Text(ImportExportModel.exportIntro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            row(String(localized: "Encrypted backup (.lgkm)"), ImportExportModel.encryptedHelp, button: String(localized: "Export…")) { askingBackupPassword = true }
            Rectangle().fill(theme.line).frame(height: 1)
            row(String(localized: "Apple Passwords CSV"), ImportExportModel.passkeysNotInCSV + " " + String(localized: "The file is not encrypted."), button: String(localized: "Export…")) {
                model.requestCSVExport()
            }
            if let message = model.exportMessage { note(message, theme.textMuted) }
            Text("Both ask for your master password first.").font(.system(size: 11.5)).foregroundStyle(theme.textFaint)
        }
    }

    private func row(_ title: String, _ detail: String, button: String, action: @escaping () -> Void) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 13, weight: .medium))
                Text(detail).font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button(button, action: action).buttonStyle(PillButtonStyle(primary: false)).disabled(model.busy)
        }
    }

    private func note(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 12.5)).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
    }

    private func card<Content: View>(_ title: String, @ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title).font(.system(size: 15, weight: .semibold))
            content()
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous).strokeBorder(theme.panelBorder))
    }
}

/// The step on screen: the review, the restore preview, a file's password or a generic CSV's columns.
enum PageSheet: Identifiable {
    case review(ImportReviewModel), restore(ImportExportModel.RestorePreview)
    case password(ImportExportModel.PasswordRequest), mapping(ImportExportModel.MappingRequest)

    var id: String {
        switch self {
        case .review(let r): "review-\(ObjectIdentifier(r).hashValue)"
        case .restore(let p): "restore-\(p.id)"
        case .password(let p): "password-\(p.id)"
        case .mapping(let m): "mapping-\(m.id)"
        }
    }

    @MainActor static func current(_ model: ImportExportModel) -> PageSheet? {
        if let r = model.review { return .review(r) }
        if let p = model.restore { return .restore(p) }
        if let p = model.passwordRequest { return .password(p) }
        if let m = model.mappingRequest { return .mapping(m) }
        return nil
    }
}

/// Asks for the password of an encrypted export or a phone backup; it is used once and not stored.
struct FilePasswordSheet: View {
    let model: ImportExportModel
    let request: ImportExportModel.PasswordRequest
    @State private var password = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(request.isPhoneBackup ? String(localized: "Restore phone backup") : String(localized: "Password needed")).font(.title3.weight(.semibold))
            Text(request.fileName).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            Text(request.prompt).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            SecureField(request.isPhoneBackup ? String(localized: "Backup password") : String(localized: "Password"), text: $password).glassField().onSubmit(submit)
            if let e = model.passwordRequest?.error { Text(e).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                if model.busy { ProgressView().controlSize(.small); Text("Opening…").foregroundStyle(theme.textMuted) }
                Spacer()
                Button("Cancel") { password = ""; model.reset() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Open", action: submit).buttonStyle(PillButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction).disabled(password.isEmpty || model.busy)
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
        .onDisappear { password = "" }
    }

    private func submit() {
        let pw = password   // captured before the Task runs
        password = ""
        Task { await model.submitPassword(pw) }
    }
}

/// The encrypted backup's password, twice; then the master password and the save panel.
struct BackupPasswordSheet: View {
    let model: ImportExportModel
    let onAccept: (String, String) -> Void
    let onClose: () -> Void
    @State private var password = ""
    @State private var again = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Encrypted backup").font(.title3.weight(.semibold))
            SecureField("Backup password", text: $password).glassField()
            SecureField("Repeat password", text: $again).glassField()
            Text("At least \(VaultExporter.minPasswordLength) characters. You'll need this password to restore the backup; it can't be recovered.")
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            if let e = model.exportMessage { Text(e).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel") { clear(); onClose() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Export…") {
                    let (p, c) = (password, again)   // captured before the fields are cleared
                    guard model.checkBackupPassword(p, confirmation: c) else { return }
                    clear()
                    onAccept(p, c)   // the master password is asked once this sheet has closed
                }
                .buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
                .disabled(password.count < VaultExporter.minPasswordLength || again.isEmpty)
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
        .onDisappear { clear() }
    }

    private func clear() { password = ""; again = "" }
}

/// The CSV plain-text warning (Windows `ExportWarning`), a sheet so the master password can follow its dismissal.
struct CSVWarningSheet: View {
    let onExport: () -> Void
    let onCancel: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Export as CSV?").font(.title3.weight(.semibold))
            Text(ImportExportModel.csvWarning).font(.system(size: 12.5)).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button("Export", action: onExport).buttonStyle(PillButtonStyle(primary: true)).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
    }
}
