import SwiftUI
import LocalAuthentication
import AppSharedMac

/// The sidebar's Sync page (Windows `SyncPage.svelte`): Wi-Fi, Cloud folder, Join with a code and Messages
/// cards, then Sync now, Leave sync and Reset sync. The pairing code opens in a sheet (QR code, address,
/// code, Copy code text), which turns into the Accept / Decline step when a device asks to join.
struct SyncPage: View {
    @Bindable var model: SyncPageModel
    @Environment(\.macTheme) private var theme
    @State private var confirmRollback = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(SyncPageModel.title).font(.system(size: 19, weight: .semibold))
                Text(SyncPageModel.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                if let info = model.info { note(info, theme.success) }
                if let error = model.error { note(error, theme.warning) }
                if !model.available { note(model.unavailableText, theme.warning) }
                wifiCard
                folderCard
                joinCard
                if !model.messages.isEmpty { messagesCard }
                HStack(spacing: 8) {
                    Button(SyncPageModel.syncNowLabel) { model.syncNow() }
                        .buttonStyle(PillButtonStyle(primary: true)).disabled(!model.available || !model.joined)
                    Spacer()
                    if model.canLeave {
                        Button(SyncPageModel.leaveLabel) { model.requestLeave() }.buttonStyle(PillButtonStyle(primary: false))
                    }
                    Button(SyncPageModel.resetLabel) { model.requestReset() }
                        .buttonStyle(PillButtonStyle(primary: false)).disabled(!model.available)
                }
                if !model.lastSyncText.isEmpty {
                    Text(model.lastSyncText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                }
            }
            .foregroundStyle(theme.text)
            .padding(18)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { model.reload() }
        .onChange(of: model.scheduler?.syncRevision) { _, _ in model.reload() }
        .onChange(of: model.pairingStage) { _, _ in model.reload() }
        .alert(model.confirmationButton + "?", isPresented: Binding(get: { model.confirmation != nil },
                                                                      set: { if !$0 { model.cancelConfirmation() } })) {
            Button(model.confirmationButton, role: .destructive) {
                let shown = model.confirmation
                Task { await model.confirm(shown) }
            }
            Button("Cancel", role: .cancel) { model.cancelConfirmation() }
        } message: { Text(model.confirmationText) }
        .sheet(isPresented: $model.showingQR) { QRSheet(model: model).macThemed() }
        .sheet(item: Binding(get: { model.removal.map(RemovalBox.init) }, set: { if $0 == nil { model.removal = nil } })) { box in
            RemoveMemberSheet(model: model, removal: box.removal).macThemed()
        }
        .sheet(item: $model.folderForm) { form in FolderPasswordSheet(model: model, form: form).macThemed() }
    }

    // MARK: cards

    private var wifiCard: some View {
        card(SyncPageModel.wifiTitle) {
            Text(model.wifiText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if model.available {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Address and port").font(.system(size: 12, weight: .medium)).foregroundStyle(theme.textMuted)
                    HStack(spacing: 8) {
                        TextField("192.168.1.20:47821", text: $model.addressText)
                            .glassField().frame(maxWidth: 260)
                            .onSubmit { model.applyAddress() }
                        if model.wifiOn {
                            Button("Use this address") { model.applyAddress() }.buttonStyle(PillButtonStyle(primary: false))
                        }
                    }
                    let choices = model.addressChoices.filter { $0 != model.addressText }
                    if !choices.isEmpty {
                        HStack(spacing: 6) {
                            ForEach(choices, id: \.self) { c in
                                Button(c) { model.addressText = c; if model.wifiOn { model.applyAddress() } }
                                    .buttonStyle(.plain).font(.system(size: 12))
                                    .padding(.horizontal, 10).padding(.vertical, 4)
                                    .background(theme.chip, in: Capsule())
                            }
                        }
                    }
                    if let e = model.addressError { Text(e).font(.system(size: 12)).foregroundStyle(theme.warning) }
                    Text(SyncPageModel.wifiIntro).font(.system(size: 11.5)).foregroundStyle(theme.textFaint)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if !model.peers.isEmpty {
                devices(SyncPageModel.pairedHeading, model.peers) { d in
                    Button("Remove…") { model.requestRemovePeer(d) }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
            HStack(spacing: 8) {
                if model.wifiOn {
                    Button(SyncPageModel.showQRLabel) { model.showQR() }.buttonStyle(PillButtonStyle(primary: true))
                    Button(SyncPageModel.wifiOffLabel) { model.setWiFi(false) }.buttonStyle(PillButtonStyle(primary: false))
                } else {
                    Button(SyncPageModel.wifiOnLabel) { model.setWiFi(true) }.buttonStyle(PillButtonStyle(primary: true))
                }
            }
            .disabled(!model.available)
            if model.licenceOnly {
                Text(SyncPageModel.licenceOnlyText).font(.system(size: 11.5)).foregroundStyle(theme.textFaint)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var folderCard: some View {
        card(SyncPageModel.folderTitle) {
            Text(model.folderText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if !model.members.isEmpty {
                devices(SyncPageModel.membersHeading, model.members) { d in
                    if !d.isSelf {
                        Button("Remove…") { model.requestRemoveMember(d) }.buttonStyle(PillButtonStyle(primary: false))
                    }
                }
            }
            if !model.unconfirmed.isEmpty {
                Text(SyncPageModel.unackedText).font(.system(size: 12.5)).foregroundStyle(theme.warning)
                    .fixedSize(horizontal: false, vertical: true)
                Button(SyncPageModel.ackLabel) { model.confirmMembers() }.buttonStyle(PillButtonStyle(primary: true))
            }
            if model.joined && model.members.isEmpty {
                Text(SyncPageModel.lanOnlyFolderHint).font(.system(size: 11.5)).foregroundStyle(theme.textFaint)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 8) {
                if !model.joined {
                    Button(SyncPageModel.createLabel) { Task { await model.pickFolder(.create) } }
                        .buttonStyle(PillButtonStyle(primary: true))
                    Button(SyncPageModel.joinFolderLabel) { Task { await model.pickFolder(.join) } }
                        .buttonStyle(PillButtonStyle(primary: false))
                    if !model.hostingAllowed { proTag }
                } else if model.members.isEmpty {
                    Button(SyncPageModel.addFolderLabel) { Task { await model.pickFolder(.add) } }
                        .buttonStyle(PillButtonStyle(primary: true))
                    Button(SyncPageModel.useFolderLabel) { Task { await model.pickFolder(.use) } }
                        .buttonStyle(PillButtonStyle(primary: false))
                } else {
                    Button(SyncPageModel.repickLabel) { Task { await model.pickFolder(nil) } }
                        .buttonStyle(PillButtonStyle(primary: false))
                }
            }
            .disabled(!model.available || model.working || model.joining)
        }
    }

    private var joinCard: some View {
        card(SyncPageModel.joinTitle) {
            Text(SyncPageModel.joinIntro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            TextField("lgk-pair:…", text: $model.joinText, axis: .vertical)
                .lineLimit(2...4).font(.system(size: 12, design: .monospaced)).glassField()
            if let code = model.verificationCode {
                VStack(alignment: .leading, spacing: 4) {
                    Text(code).font(.system(size: 28, weight: .semibold, design: .monospaced)).accessibilityLabel("Verification code")
                    Text(SyncWording.verificationCodeHint).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                }
            }
            if model.hostNotFound {
                Text(SyncWording.hostNotFoundTitle).font(.system(size: 12.5, weight: .semibold))
                Text(SyncWording.findAgainHint).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 8) {
                Button(SyncPageModel.joinLabel) { Task { await model.join() } }
                    .buttonStyle(PillButtonStyle(primary: !model.joined))
                    .disabled(!model.available || model.joining || model.joinText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                if model.hostNotFound {
                    Button(SyncWording.findAgainAction) { Task { await model.findAgain() } }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(!model.available || model.joining || model.joinText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                if model.joining {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { model.cancelJoin() }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
        }
    }

    private var messagesCard: some View {
        card(SyncPageModel.messagesTitle) {
            ForEach(model.messages) { m in
                if m.kind == "vault-rollback" {
                    Text(SyncWording.rollbackTitle).font(.system(size: 13, weight: .semibold)).foregroundStyle(theme.danger)
                }
                Text("• " + m.text).font(.system(size: 12.5))
                    .foregroundStyle(m.severity == .error ? theme.danger : (m.severity == .warning ? theme.warning : theme.textMuted))
                    .fixedSize(horizontal: false, vertical: true)
                if m.kind == "vault-rollback" {
                    Button(SyncWording.rollbackAction) { confirmRollback = true }.buttonStyle(PillButtonStyle(primary: true))
                }
                if m.kind == "peer-vault-rollback", !m.detail.isEmpty, let coordinator = model.coordinator {
                    Button(SyncWording.peerRollbackDismiss) {
                        Task { await coordinator.dismissPeerRollback(m.detail); model.reload() }
                    }.buttonStyle(PillButtonStyle(primary: false))
                }
            }
        }
        .alert(SyncWording.rollbackConfirmTitle, isPresented: $confirmRollback) {
            Button("Keep this copy") {
                guard let coordinator = model.coordinator else { return }
                Task {
                    await coordinator.acknowledgeRollback(reauthenticate: { await Self.confirmOwner() })
                    model.reload()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { Text(SyncWording.onPhone(SyncWording.rollbackConfirmText)) }
    }

    /// Touch ID or the Mac's login password, asked again for this step (no reuse of the unlock).
    @MainActor static func confirmOwner() async -> Bool {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        return (try? await ctx.evaluatePolicy(.deviceOwnerAuthentication,
                                              localizedReason: String(localized: "confirm that you restored this vault"))) ?? false
    }

    // MARK: pieces

    private var proTag: some View {
        Text("Pro").font(.system(size: 11, weight: .semibold)).foregroundStyle(theme.accent)
            .padding(.horizontal, 8).padding(.vertical, 2)
            .overlay(Capsule().strokeBorder(theme.accent.opacity(0.6)))
    }

    private func note(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 12.5)).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
    }

    private func devices<Trailing: View>(_ heading: String, _ list: [SyncPageModel.Device],
                                         @ViewBuilder trailing: @escaping (SyncPageModel.Device) -> Trailing) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(heading).font(.system(size: 12, weight: .medium)).foregroundStyle(theme.textMuted).padding(.bottom, 4)
            ForEach(Array(list.enumerated()), id: \.element.id) { i, d in
                if i > 0 { Rectangle().fill(theme.line).frame(height: 1) }
                HStack(spacing: 10) {
                    Image(systemName: d.isSelf ? "laptopcomputer" : "desktopcomputer").foregroundStyle(theme.textMuted).frame(width: 18)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(d.name).font(.system(size: 13))
                        if !d.detail.isEmpty {
                            Text(d.detail).font(.system(size: 11.5)).foregroundStyle(d.unconfirmed ? theme.warning : theme.textMuted)
                        }
                    }
                    Spacer()
                    trailing(d)
                }
                .padding(.vertical, 7)
            }
        }
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

private struct RemovalBox: Identifiable {
    let removal: SyncPageModel.Removal
    var id: String { removal.id }
}

/// The pairing sheet: the QR code with this Mac's address and the offer code, then (when a device asks)
/// its name, the 6-digit code and key fingerprint with Accept / Decline, then Undo / Keep.
struct QRSheet: View {
    let model: SyncPageModel
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch model.pairingStage {
            case .confirm, .adding: confirmStep
            case .paired: pairedStep
            default: codeStep
            }
        }
        .padding(24)
        .frame(width: 520)
        .background(WashBackground())
        .foregroundStyle(theme.text)
    }

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Scan this code with LocalGateKeys on the other device").font(.title3.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: 18) {
                if let text = model.qrText, let image = SyncPageModel.qrImage(text) {
                    Image(nsImage: image).interpolation(.none).resizable().frame(width: 260, height: 260)
                        .accessibilityLabel("Pairing QR code")
                } else {
                    RoundedRectangle(cornerRadius: 8).fill(theme.card).frame(width: 260, height: 260)
                        .overlay(Text(model.pairingMessage ?? HostPairingModel.closedText).font(.system(size: 12))
                            .foregroundStyle(theme.textMuted).padding())
                }
                VStack(alignment: .leading, spacing: 6) {
                    if !model.offerEndpoint.isEmpty {
                        Text("This Mac").font(.system(size: 12)).foregroundStyle(theme.textMuted)
                        Text(model.offerEndpoint).font(.system(size: 15, weight: .semibold, design: .monospaced))
                    }
                    if let code = model.offerCode { Text("Code: \(code)").font(.system(size: 14, design: .monospaced)) }
                    Text(HostPairingModel.pairHint).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text(String(localized: "On another PC, use Join with a code and paste the code text instead."))
                .font(.system(size: 12)).foregroundStyle(theme.textMuted)
            Text(model.countdown).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
            if let m = model.pairingMessage { Text(m).font(.system(size: 12.5)).foregroundStyle(theme.textMuted) }
            HStack {
                Button(SyncPageModel.copyLabel) { model.copyCodeText() }.buttonStyle(GlassButtonStyle())
                Spacer()
                Button("Close") { model.closeQR() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
            }
        }
    }

    private var confirmStep: some View {
        VStack(alignment: .leading, spacing: 10) {
            let r = model.request
            Text(r.map { String(localized: "Add \($0.name)?") } ?? String(localized: "Add this device?")).font(.title3.weight(.semibold))
            if let r { Text(r.message).font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true) }
            Text(r?.code ?? "").font(.system(size: 40, weight: .semibold, design: .monospaced))
                .accessibilityLabel("Verification code").frame(maxWidth: .infinity)
                .padding(.vertical, 8)
            Text("\(HostPairingModel.acceptHint) \(HostPairingModel.declineHint)").font(.system(size: 12)).foregroundStyle(theme.textMuted)
            if let f = r?.fingerprint, !f.isEmpty {
                Text("Key fingerprint: \(f)").font(.system(size: 12, design: .monospaced)).foregroundStyle(theme.textMuted)
            }
            if model.pairingStage == .confirm, let s = model.secondsLeft {
                Text(HostPairingModel.declinesText(s)).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            HStack {
                Spacer()
                Button("Decline") { model.decide(false) }.buttonStyle(PillButtonStyle(primary: false)).disabled(model.pairingStage == .adding)
                Button(model.pairingStage == .adding ? String(localized: "Adding…") : String(localized: "Accept")) { model.decide(true) }
                    .buttonStyle(PillButtonStyle(primary: true)).disabled(model.pairingStage == .adding)
            }
        }
    }

    private var pairedStep: some View {
        VStack(alignment: .leading, spacing: 10) {
            let p = model.paired
            Text("Paired: \(p?.name ?? "")").font(.title3.weight(.semibold))
            if let p { Text(p.message).font(.system(size: 13)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("Undo") { model.undoPairing() }.buttonStyle(PillButtonStyle(primary: false))
                Button("Keep") { model.keepPairing() }.buttonStyle(PillButtonStyle(primary: true))
            }
        }
    }
}

/// "Remove a device…" on the Cloud folder card: a new sync password, entered twice (Windows rotation form).
struct RemoveMemberSheet: View {
    let model: SyncPageModel
    let removal: SyncPageModel.Removal
    @State private var password = ""
    @State private var again = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Remove \(removal.name)").font(.title3.weight(.semibold))
            Text(removal.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Sync password", text: $password).glassField()
            SecureField("Enter it again", text: $again).glassField()
            Text("At least 12 characters, rated Strong or better.").font(.system(size: 12)).foregroundStyle(theme.textMuted)
            Text(SyncPageModel.passwordAdvice).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            if let e = model.error { Text(e).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel") { model.removal = nil }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(model.working ? String(localized: "Working…") : String(localized: "Continue")) { Task { _ = await model.removeMember(password: password, again: again) } }
                    .buttonStyle(PillButtonStyle(primary: true))
                    .disabled(model.working || password.isEmpty || again.isEmpty)
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
    }
}

/// The sync password for a picked cloud folder: a new one entered twice (create, add) or the group's one
/// (join, use). The password is never stored.
struct FolderPasswordSheet: View {
    let model: SyncPageModel
    let form: SyncPageModel.FolderForm
    @State private var password = ""
    @State private var again = ""
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(form.title).font(.title3.weight(.semibold))
            Text(form.intro).font(.system(size: 12.5)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
            SecureField("Sync password", text: $password).glassField()
            if form.isNew {
                SecureField("Enter it again", text: $again).glassField()
                Text("At least 12 characters, rated Strong or better.").font(.system(size: 12)).foregroundStyle(theme.textMuted)
                Text(SyncPageModel.passwordAdvice).font(.system(size: 12)).foregroundStyle(theme.textMuted)
            }
            if let e = model.error { Text(e).font(.system(size: 12.5)).foregroundStyle(theme.warning) }
            HStack {
                Spacer()
                Button("Cancel") { model.cancelFolder() }.buttonStyle(GlassButtonStyle()).keyboardShortcut(.cancelAction)
                Button(model.working ? String(localized: "Working…") : (form.isNew ? String(localized: "Create") : String(localized: "Join"))) {
                    let pw = password, pw2 = again
                    Task { _ = await model.submitFolder(password: pw, again: pw2) }
                }
                .buttonStyle(PillButtonStyle(primary: true))
                .disabled(model.working || password.isEmpty || (form.isNew && again.isEmpty))
            }
        }
        .padding(24).frame(width: 460).background(WashBackground()).foregroundStyle(theme.text)
        .alert(SyncPageModel.newKeyTitle, isPresented: Binding(get: { model.freshKeyText != nil },
                                                               set: { if !$0 { model.freshKeyText = nil } })) {
            Button("Continue") {
                // Captured now: closing the alert clears freshKeyText before the Task runs.
                let pw = password, pw2 = again
                Task { _ = await model.submitFolder(password: pw, again: pw2, freshKeyConfirmed: true) }
            }
            Button("Cancel", role: .cancel) { model.freshKeyText = nil }
        } message: { Text(model.freshKeyText ?? "") }
    }
}
