import SwiftUI
import LGKCore
import AppSharedMac

/// Security centre › "Last backup restore test" with "Test now", the weekly switch and "Print vault health report"
/// (sub-plan 12). "Test now" asks for the backup password, restores the newest scheduled backup into
/// `<vault folder>/restore-test/<uuid>` (removed again at once) and forgets the password.
struct RestoreTestPanel: View {
    let settings: AppSettings
    let backup: RecoveryStatus?
    @Environment(\.macTheme) private var theme
    @State private var model = RestoreTestModel(folder: MacAppEnvironment.vaultDirectory())
    @State private var asking = false
    @State private var password = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(RestoreTestModel.title).font(.system(size: 13))
                    Text(model.rowText).font(.system(size: 11))
                        .foregroundStyle(model.last?.ok == false ? theme.danger : theme.textMuted)
                    if model.isDue() {
                        Text(RestoreTestModel.dueText).font(.system(size: 11)).foregroundStyle(theme.warning)
                    }
                }
                Spacer(minLength: 8)
                if model.running { ProgressView().controlSize(.small) }
                Button(RestoreTestModel.testNow) { password = ""; asking = true }
                    .buttonStyle(PillButtonStyle(primary: false))
                    .disabled(model.running)
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            Toggle(RestoreTestModel.weeklyLabel, isOn: $model.weekly)
                .font(.system(size: 13))
                .padding(.horizontal, 14).padding(.vertical, 9)
            HStack {
                Text(HealthReport.title).font(.system(size: 13))
                Spacer(minLength: 8)
                Button(HealthReport.printLabel) { printReport() }.buttonStyle(PillButtonStyle(primary: false))
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
        }
        .alert(RestoreTestModel.testNow, isPresented: $asking) {
            SecureField("Backup password", text: $password)
            Button(RestoreTestModel.testNow) { runTest() }
            Button("Cancel", role: .cancel) { password = "" }
        } message: {
            Text(RestoreTestModel.passwordPrompt)
        }
    }

    private func runTest() {
        let typed = password
        password = ""
        let schedule = MacAppEnvironment.backupSchedule
        let found = schedule?.newestScheduledBackup()
        let noBackup: RestoreTest.Restorer = { @Sendable _, _ in throw RestoreTest.Failure(.noBackup) }
        let restorer = schedule?.restoreTestRestorer(password: typed) ?? noBackup
        Task { await model.run(backup: found?.backup, scope: found?.scope, restore: restorer) }
    }

    private func printReport() {
        var factors = [String(localized: "Master password")]
        if settings.touchIDUnlock { factors.append(String(localized: "Touch ID")) }
        let input = HealthReport.input(factors: factors, lastBackup: backup?.lastBackup, restoreTest: model.rowText,
                                       sync: MacAppEnvironment.syncScheduler?.coordinator,
                                       build: SecurityModel.bundleVersion, isPro: MacAppEnvironment.pro.isPro)
        EmergencyKitDocument.print(blocks: HealthReport.blocks(input), jobTitle: HealthReport.title)
    }
}
