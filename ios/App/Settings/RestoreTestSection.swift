import SwiftUI
import UniformTypeIdentifiers
import AppShared

/// Settings › Lock & security: "Last backup restore test" with "Test now", the weekly switch and "Print vault health
/// report" (sub-plan 12). The iPhone has no scheduled backups: "Test now" asks for a phone backup (`.lgkm`) and its
/// password, restores it into a scratch folder in the app's container (`RestoreTest`), and forgets both.
struct RestoreTestSection: View {
    let pro: ProModel
    let sync: SyncCoordinator
    @State private var model = RestoreTestModel(folder: RestoreTestModel.defaultFolder())
    @State private var picking = false
    @State private var picked: URL?
    @State private var password = ""
    @State private var masterPassword = ""
    /// The picked file is a computer's full backup (`.lgk`/`.lgkfull`): the prompt also asks for its master password.
    @State private var pickedIsComputerBackup = false

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 4) {
                Text(RestoreTestModel.title)
                Text(model.rowText).font(.footnote).foregroundStyle(model.last?.ok == false ? Palette.danger : Palette.secondaryText)
                if model.isDue() {
                    Text(RestoreTestModel.dueText).font(.footnote).foregroundStyle(Palette.warning)
                }
            }
            Button(RestoreTestModel.testNow) { picking = true }
                .disabled(model.running)
            Toggle(RestoreTestModel.weeklyLabel, isOn: $model.weekly)
            Button(HealthReport.printLabel) { printReport() }
        }
        .listRowBackground(Palette.groupSurface)
        .fileImporter(isPresented: $picking, allowedContentTypes: Self.backupTypes) { result in
            if case .success(let url) = result {
                // A computer's full backup also needs that computer's master password (iCloud Drive files included).
                let scoped = url.startAccessingSecurityScopedResource()
                pickedIsComputerBackup = RestoreTest.isComputerBackup(url)
                if scoped { url.stopAccessingSecurityScopedResource() }
                picked = url
            }
        }
        .alert(RestoreTestModel.testNow, isPresented: Binding(get: { picked != nil }, set: { _ in })) {
            // Both buttons clear the file and the password themselves (after the test has copied them).
            SecureField("Backup password", text: $password)
            if pickedIsComputerBackup {
                SecureField(String(localized: "Master password of that computer"), text: $masterPassword)
            }
            Button(RestoreTestModel.testNow) { runTest() }
            Button("Cancel", role: .cancel) { finish() }
        } message: {
            Text(pickedIsComputerBackup ? String(localized: "A full backup from a computer: type its backup password and the master password of the computer that made it. Nothing is restored or kept.")
                                         : RestoreTestModel.passwordPrompt)
        }
    }

    static var backupTypes: [UTType] {
        ["lgkm", "lgk", "lgkfull"].compactMap { UTType(filenameExtension: $0) } + [.data]
    }

    private func runTest() {
        let url = picked, typed = password, master = masterPassword, computer = pickedIsComputerBackup
        finish()
        let restorer = computer ? RestoreTest.computerBackup(password: typed, masterPassword: master)
                                : RestoreTest.phoneBackup(password: typed)
        Task { await model.run(backup: url, restore: restorer) }
    }

    /// Drops the picked file and the typed password.
    private func finish() {
        picked = nil
        password = ""
        masterPassword = ""
        pickedIsComputerBackup = false
    }

    private func printReport() {
        var factors = [String(localized: "Face ID, Touch ID or the device passcode")]
        if AppPasswordMode.isOn { factors.append(String(localized: "App password")) }
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let input = HealthReport.input(factors: factors, lastBackup: nil, restoreTest: model.rowText, sync: sync,
                                       build: build, isPro: pro.isPro)
        EmergencyKitDocument.print(blocks: HealthReport.blocks(input))
    }
}
