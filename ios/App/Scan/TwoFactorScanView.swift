import SwiftUI
import PhotosUI
import AppShared

/// Loads a photo chosen with PhotosPicker (no photo-library permission: the picker runs out of process) and
/// reads its 2FA QR codes off the main actor. The image bytes stay in memory and are dropped afterwards.
enum PhotoQRLoader {
    static func payloads(from item: PhotosPickerItem) async -> Result<[String], TwoFactorQRDecoder.Failure> {
        guard let data = try? await item.loadTransferable(type: Data.self) else { return .failure(.unreadable) }
        return await Task.detached(priority: .userInitiated) {
            do { return .success(try TwoFactorQRDecoder.payloads(inImageData: data)) }
            catch let f as TwoFactorQRDecoder.Failure { return .failure(f) }
            catch { return .failure(.unreadable) }
        }.value
    }
}

/// "Scan QR code" from the Vault screen: the camera or a photo, then the key goes to a matching login (or a
/// new one, opened in the editor by `onNewLogin` once this sheet has gone), or an authenticator export's
/// accounts are chosen and imported in one go.
struct TwoFactorScanView: View {
    @State var model: TwoFactorScanModel
    /// The prefilled new login, opened by the caller after this sheet is dismissed.
    let onNewLogin: (EditorModel) -> Void
    /// Something was saved (the list reloads).
    let onSaved: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var cameraOn = false
    @State private var cameraRun = 0
    @State private var photo: PhotosPickerItem?
    @State private var reading = false
    @State private var importing = false
    @State private var decoding: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            content
                .scrollContentBackground(.hidden)
                .lgkAuroraBackground()
                .navigationTitle("Scan QR code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button(isFinished ? String(localized: "Done") : String(localized: "Cancel")) { close() } }
                }
        }
        .sheet(isPresented: $model.showUpgrade) { UpgradeView(pro: model.pro) }
        .onChange(of: photo) { _, item in read(item) }
        .onChange(of: model.step) { _, step in
            if case .newLogin = step, let editor = model.newLoginEditor() {
                model.reset(); onNewLogin(editor); dismiss()
            }
        }
        .onDisappear { decoding?.cancel(); model.reset() }
        .alert("Replace the 2FA code?", isPresented: Binding(get: { model.confirmReplaceID != nil }, set: { if !$0 { model.cancelReplacements() } })) {
            Button("Replace", role: .destructive) {
                if let id = model.confirmReplaceID, model.addKey(to: id, confirmed: true) == .saved { onSaved() }
            }
            Button("Cancel", role: .cancel) { model.cancelReplacements() }
        } message: { Text("This login already has a 2FA code. The scanned code replaces it.") }
        .alert("Replace 2FA codes?", isPresented: Binding(get: { model.replaceQuestion != nil }, set: { if !$0 { model.cancelReplacements() } })) {
            Button("Replace", role: .destructive) { model.confirmReplacements(); runImport() }
            Button("Cancel", role: .cancel) { model.cancelReplacements() }
        } message: { Text("These logins already have a 2FA code that will be replaced: \((model.replaceQuestion ?? []).joined(separator: ", ")).") }
    }

    private var isFinished: Bool { if case .finished = model.step { true } else { false } }

    @ViewBuilder private var content: some View {
        switch model.step {
        case .scanning, .newLogin: sources(intro: Self.intro)
        case .nextPart(let received, let total):
            sources(intro: String(localized: "Part \(received) of \(total) of this export was read. Show the next QR code in your authenticator app."))
        case .chooseLogin(let account, let matches): chooser(account, matches)
        case .checklist: checklist
        case .finished(let summary):
            Form { Section { Label(summary, systemImage: "checkmark.circle").foregroundStyle(Palette.text) } }
        }
    }

    static let intro = String(localized: "Scan the QR code a website shows when you turn on two-factor authentication, or a Google Authenticator export (Transfer accounts › Export).")

    @ViewBuilder private func sources(intro: String) -> some View {
        if cameraOn {
            QRScanner(onCode: { code in
                cameraOn = false
                model.scanned([code])
                if case .nextPart = model.step { cameraRun += 1; cameraOn = model.error == nil }
            }, onUnavailable: { cameraOn = false; model.failed(message: EditorModel.totpCameraMessage) })
            .id(cameraRun)
            .ignoresSafeArea()
        } else {
            Form {
                Section {
                    Text(intro).foregroundStyle(Palette.secondaryText)
                    Button { cameraOn = true } label: { Label("Use camera", systemImage: "camera") }
                    PhotosPicker(selection: $photo, matching: .images, photoLibrary: .shared()) {
                        Label("Choose from Photos", systemImage: "photo.on.rectangle")
                    }
                    if reading { ProgressView("Reading the image…") }
                } footer: {
                    Text("The image is read on this iPhone and is not saved.")
                }
                .listRowBackground(Palette.groupSurface)
                if let error = model.error {
                    Section { Text(error).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
                }
                if let notice = model.notice {
                    Section { Text(notice).foregroundStyle(Palette.secondaryText) }.listRowBackground(Palette.groupSurface)
                }
            }
        }
    }

    private func chooser(_ account: OTPAccount, _ matches: [ScanLoginMatch]) -> some View {
        Form {
            Section {
                Text(Self.accountLine(account)).font(.headline).foregroundStyle(Palette.text)
                Text("Add this 2FA key to one of these logins, or create a new login for it.").foregroundStyle(Palette.secondaryText)
            }
            .listRowBackground(Palette.groupSurface)
            Section("Matching logins") {
                ForEach(matches) { m in
                    Button { if model.addKey(to: m.id) == .saved { onSaved() } } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(m.title.isEmpty ? m.site : m.title).foregroundStyle(Palette.text)
                            Text([m.username, m.site].filter { !$0.isEmpty }.joined(separator: " · "))
                                .font(.subheadline).foregroundStyle(Palette.secondaryText)
                            if m.hasKey { Text("(replaces its 2FA code)").font(.footnote).foregroundStyle(Palette.warning) }
                        }
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
            Section {
                Button { openNewLogin() } label: { Label("Create a new login", systemImage: "plus") }
            }
            .listRowBackground(Palette.groupSurface)
            if let error = model.error {
                Section { Text(error).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
            }
        }
    }

    private var checklist: some View {
        Form {
            if let notice = model.notice {
                Section { Text(notice).foregroundStyle(Palette.secondaryText) }.listRowBackground(Palette.groupSurface)
            }
            Section {
                ForEach(Array(model.accounts.enumerated()), id: \.offset) { i, a in exportRow(i, a) }
            } header: {
                Text("\(model.accounts.count) accounts in this export")
            } footer: {
                Text("A new login needs its website. It gets a generated password and the tag needs-password until you set your real one.")
            }
            .listRowBackground(Palette.groupSurface)
            if !model.skipped.isEmpty {
                Section("Can't be added") {
                    ForEach(Array(model.skipped.enumerated()), id: \.offset) { _, s in
                        VStack(alignment: .leading) {
                            Text(Self.accountLine(OTPAccount(issuer: s.issuer, account: s.account, config: TOTPConfig(secret: ""))))
                            Text(s.reason).font(.footnote).foregroundStyle(Palette.secondaryText)
                        }
                    }
                }
                .listRowBackground(Palette.groupSurface)
            }
            Section {
                Button(action: runImport) {
                    Text(String(localized: "Add \(model.selected.count) accounts"))
                }
                .disabled(!model.canAdd || importing)
                if let error = model.error { Text(error).foregroundStyle(Palette.danger) }
            }
            .listRowBackground(Palette.groupSurface)
        }
    }

    @ViewBuilder private func exportRow(_ i: Int, _ a: OTPAccount) -> some View {
        let checked = model.selected.contains(i)
        VStack(alignment: .leading, spacing: 8) {
            Toggle(isOn: Binding(get: { checked }, set: { if $0 { model.selected.insert(i) } else { model.selected.remove(i) } })) {
                Text(Self.accountLine(a)).foregroundStyle(Palette.text)
            }
            .tint(Palette.accent)
            if checked, model.rows.indices.contains(i) {
                Picker("Add to", selection: $model.rows[i].target) {
                    Text("New login").tag(TwoFactorScanModel.Destination.newLogin)
                    ForEach(model.rows[i].matches) { m in
                        Text(m.hasKey ? String(localized: "Add to \(m.title.isEmpty ? m.site : m.title) (replaces its 2FA code)")
                                 : String(localized: "Add to \(m.title.isEmpty ? m.site : m.title)"))
                            .tag(TwoFactorScanModel.Destination.existing(m.id))
                    }
                }
                .pickerStyle(.menu)
                if model.rows[i].target == .newLogin {
                    TextField("Website, e.g. example.com", text: $model.rows[i].website)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    if let suggestion = model.rows[i].suggestion, model.rows[i].website.isEmpty {
                        Button("From the QR code: \(suggestion) — use it?") { model.rows[i].website = suggestion }
                            .font(.footnote).buttonStyle(.borderless)
                    }
                }
            }
        }
    }

    private func runImport() {
        importing = true
        Task {
            if await model.importSelected() != nil { onSaved() }
            importing = false
        }
    }

    static func accountLine(_ a: OTPAccount) -> String {
        [a.issuer, a.account].filter { !$0.isEmpty }.joined(separator: " — ").ifEmpty(String(localized: "Unnamed account"))
    }

    private func openNewLogin() {
        guard let editor = model.newLoginEditor() else { return }
        model.reset(); onNewLogin(editor); dismiss()
    }

    private func read(_ item: PhotosPickerItem?) {
        guard let item else { return }
        photo = nil
        reading = true
        let generation = model.generation
        decoding?.cancel()
        decoding = Task {
            let result = await PhotoQRLoader.payloads(from: item)
            guard !Task.isCancelled else { return }
            reading = false
            switch result {
            case .success(let payloads): model.scanned(payloads, generation: generation)
            case .failure(let f): model.failed(f, generation: generation)
            }
        }
    }

    private func close() { decoding?.cancel(); model.reset(); dismiss() }
}

extension String {
    func ifEmpty(_ fallback: String) -> String { isEmpty ? fallback : self }
}
