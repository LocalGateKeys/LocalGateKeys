import SwiftUI
import LGKCore
import AppSharedMac

/// Share a collection, or join a shared one, on the Mac (sub-plan 07 task 5i): the iPhone's `CollectionShareModel` (task
/// 5h; desktop `CollectionShare.svelte`) with a Mac layout, shown in the Collections sheet in place of the list. With a
/// collection: Share (folder, your name, the share password twice, "Members can edit"), or once shared its status (with
/// Join again), the mode and folder, People (Remove with a new share password twice, after a confirmation), Waiting for
/// approval (Let them in, by name), Removed, and Leave / Stop sharing. Without one: Join a shared collection (folder and
/// password); after the join it shows that collection. The folder comes from `MacFolderPicker`. Sharing asks for the
/// master password first, through the window's `StrictItemGate` (desktop `_confirm_handover`, create only); removing a
/// person asks for a confirmation only, as on the desktop. The free plan gets the upgrade sheet for Share and Join.
/// Password fields are emptied by every action and when the page closes.
struct MacCollectionSharePage: View {
    @State private var model: CollectionShareModel
    let pro: ProModel?
    /// After a change: the collections and the window's list reload.
    let onChange: () -> Void
    /// Back to the Collections list.
    let onBack: () -> Void
    /// Turns a picked folder into a bookmark (`MacFolderPicker` in the app).
    private let chooseFolder: @MainActor () -> URL?
    @State private var removing: CollectionShareModel.Member?
    @State private var confirmingRemove = false
    @State private var confirmingApprove = false
    @State private var confirmingLeave = false
    @State private var confirmingForget = false
    @Environment(\.macTheme) private var theme

    typealias Words = CollectionShareModel.Words

    /// The master password prompt's title ("Sharing a collection asks for the master password each time…").
    nonisolated static let shareGateTitle = String(localized: "Sharing a collection")

    init(collectionID: String?, sync: SyncCoordinator, gate: StrictItemGate?, pro: ProModel?,
         onChange: @escaping () -> Void = {}, onBack: @escaping () -> Void,
         chooseFolder: @escaping @MainActor () -> URL? = { MacFolderPicker.choose() }) {
        _model = State(initialValue: Self.makeModel(collectionID: collectionID, sync: sync, gate: gate))
        self.pro = pro; self.onChange = onChange; self.onBack = onBack; self.chooseFolder = chooseFolder
    }

    /// The share model with the Mac's owner check: the master password through `gate` (no gate: refused).
    @MainActor static func makeModel(collectionID: String?, sync: SyncCoordinator, gate: StrictItemGate?) -> CollectionShareModel {
        CollectionShareModel(collectionID: collectionID, sync: sync, confirmOwner: { await MacCollectionSharePage.confirmOwner(gate) })
    }

    /// Before a collection's items go to a folder: the master password, never Touch ID, no grace period. False when the
    /// prompt was cancelled, another prompt is open, or there is no gate.
    @MainActor static func confirmOwner(_ gate: StrictItemGate?) async -> Bool {
        guard let gate else { return false }
        return await gate.confirmMasterPassword(title: shareGateTitle, action: Words.shareButton)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Button { model.clearPasswords(); onBack() } label: { Label("Collections", systemImage: "chevron.left") }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
            }
            Text(title).font(.system(size: 18, weight: .semibold)).lineLimit(2)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if model.collectionID == nil {
                        joinSection
                    } else if let summary = model.summary {
                        statusSection(summary)
                        if summary.shared {
                            sharedSections(summary)
                        } else if let link = summary.linked {
                            linkedSection(link)
                        } else {
                            shareSection
                        }
                    }
                    if let message = model.message {
                        Text(message).font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                    }
                    if let error = model.error {
                        Text(error).font(.system(size: 13)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        Text(CollectionShareModel.helpText)
                        if model.collectionID != nil { Text(CollectionShareModel.ownerLossText) }
                    }
                    .font(.system(size: 12)).foregroundStyle(theme.textMuted).fixedSize(horizontal: false, vertical: true)
                }
                .disabled(model.busy)
            }
            .frame(minHeight: 260, maxHeight: 460)
        }
        .onAppear { model.reload() }
        .onDisappear { model.clearPasswords() }
        .sheet(item: $removing, onDismiss: { model.clearPasswords() }) { member in
            removeSheet(member).macThemed()
        }
        // Without a Pro model (previews) there is no sheet to show, so none opens.
        .sheet(isPresented: Binding(get: { model.showUpgrade && pro != nil }, set: { model.showUpgrade = $0 })) {
            if let pro { MacUpgradeSheet(pro: pro, reason: .sync, onClose: { model.showUpgrade = false }).macThemed() }
        }
        .alert(CollectionShareModel.approveTitle, isPresented: $confirmingApprove) {
            Button(Words.letIn) { Task { if await model.approve() { onChange() } } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(CollectionShareModel.approveText(names: model.approvalNames ?? "",
                                                  collection: model.summary?.collectionName ?? ""))
        }
        .alert(model.summary?.isOwner == true ? CollectionShareModel.stopTitle : CollectionShareModel.leaveTitle,
               isPresented: $confirmingLeave) {
            Button(model.summary?.isOwner == true ? Words.stopSharing : Words.leave, role: .destructive) {
                Task { if await model.leave() { onChange() } }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            let name = SyncWording.sanitize(model.summary?.collectionName ?? "")
            Text(model.summary?.isOwner == true ? CollectionShareModel.stopText(name) : CollectionShareModel.leaveText(name))
        }
        .alert(CollectionShareModel.forgetLinkTitle, isPresented: $confirmingForget) {
            Button(Words.forgetLink, role: .destructive) { Task { if await model.forgetLink() { onChange() } } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(CollectionShareModel.forgetLinkText(SyncWording.sanitize(model.summary?.collectionName ?? "")))
        }
    }

    // MARK: - Shared by another of this person's devices

    /// A received share link (final review finding 4): which role that device has, and Forget share link for a device
    /// that was lost or reset (asks first).
    private func linkedSection(_ link: CollectionShares.Link) -> some View {
        card {
            Text(CollectionShareModel.linkedText(link)).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            Text(CollectionShareModel.forgetLinkHintText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(Words.forgetLink) { confirmingForget = true }
                    .buttonStyle(PillButtonStyle(primary: false)).foregroundStyle(theme.danger)
                    .disabled(model.busy)
            }
        }
    }

    private var title: String {
        guard let summary = model.summary else { return Words.joinTitle }
        return CollectionShareModel.shareTitle(summary.collectionName)
    }

    // MARK: - Join

    private var joinSection: some View {
        card {
            Text(CollectionShareModel.joinIntroText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            folderRow
            field(Words.yourName) { TextField(Words.namePlaceholder, text: $model.name).glassField() }
            field(Words.password) { SecureField(Words.password, text: $model.password).glassField() }
            HStack {
                Spacer()
                Button(Words.join) { Task { if await model.join() { onChange() } } }
                    .buttonStyle(PillButtonStyle(primary: true))
                    .disabled(model.picked == nil || model.password.isEmpty || model.busy)
            }
        }
    }

    // MARK: - Share

    private var shareSection: some View {
        card {
            Text(CollectionShareModel.introText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            folderRow
            field(Words.yourName) { TextField(Words.namePlaceholder, text: $model.name).glassField() }
            field(Words.password) { SecureField(Words.password, text: $model.password).glassField() }
            field(Words.passwordAgain) { SecureField(Words.passwordAgain, text: $model.passwordAgain).glassField() }
            Toggle(Words.canEdit, isOn: $model.membersCanEdit).toggleStyle(.checkbox)
            Text(CollectionShareModel.modeFixedText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button(Words.shareButton) { Task { if await model.share() { onChange() } } }
                    .buttonStyle(PillButtonStyle(primary: true))
                    .disabled(model.picked == nil || model.password.isEmpty || model.passwordAgain.isEmpty || model.busy)
            }
        }
    }

    // MARK: - Shared

    @ViewBuilder private func sharedSections(_ summary: CollectionShareModel.Summary) -> some View {
        if summary.sharedTwice {
            // Shared from two of this person's devices (re-review wave B, B1): one share should be stopped or left.
            Text(CollectionShareModel.sharedTwiceText).font(.system(size: 13)).foregroundStyle(theme.danger)
                .fixedSize(horizontal: false, vertical: true)
        }
        card {
            Text(summary.modeText ?? "")
            if !summary.folder.isEmpty {
                HStack {
                    Text(Words.folder).foregroundStyle(theme.textMuted)
                    Spacer()
                    Text(summary.folder).lineLimit(1)
                }
            }
            Text(CollectionShareModel.modeFixedText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        if summary.canUpgradeShare {
            // The owner of a share v1 collection: upgrade to share v2 with the share password typed twice.
            heading(CollectionShareModel.upgradeTitle)
            card {
                Text(CollectionShareModel.upgradeText).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                field(Words.password) { SecureField(Words.password, text: $model.password).glassField() }
                field(Words.passwordAgain) { SecureField(Words.passwordAgain, text: $model.passwordAgain).glassField() }
                HStack {
                    Spacer()
                    Button(Words.upgradeButton) { Task { if await model.upgradeShare() { onChange() } } }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(model.password.isEmpty || model.passwordAgain.isEmpty || model.busy)
                }
            }
        }
        heading(Words.people)
        card {
            ForEach(summary.members) { member in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: member.isSelf ? "\(member.name) (\(Words.you))" : member.name)
                        Text(member.stateText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    }
                    Spacer()
                    if member.removable {
                        Button(Words.remove) { model.clearPasswords(); model.dismissMessages(); removing = member }
                            .buttonStyle(.plain).foregroundStyle(theme.danger)
                    }
                }
            }
        }
        if !summary.pending.isEmpty {
            heading(Words.waiting)
            card {
                ForEach(summary.pending) { member in
                    Toggle(member.name, isOn: Binding(
                        get: { model.selectedPending.contains(member.id) },
                        set: { on in if on { model.selectedPending.insert(member.id) } else { model.selectedPending.remove(member.id) } }))
                        .toggleStyle(.checkbox)
                }
                Text(CollectionShareModel.waitingHintText).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button(Words.letIn) { confirmingApprove = true }
                        .buttonStyle(PillButtonStyle(primary: true))
                        .disabled(model.approvalNames == nil || model.busy)
                }
            }
        }
        if !summary.removed.isEmpty {
            heading(Words.removedHeading)
            card {
                ForEach(summary.removed) { removed in
                    HStack {
                        Text(removed.name)
                        Spacer()
                        Text(Date(timeIntervalSince1970: TimeInterval(removed.at)), style: .date).foregroundStyle(theme.textMuted)
                    }
                }
            }
        }
        HStack {
            Spacer()
            Button(summary.isOwner ? Words.stopSharing : Words.leave) { confirmingLeave = true }
                .buttonStyle(PillButtonStyle(primary: false)).foregroundStyle(theme.danger)
                .disabled(model.busy)
        }
    }

    // MARK: - Parts

    /// The last share run's status; Join again (with the share password) after a lost join.
    @ViewBuilder private func statusSection(_ summary: CollectionShareModel.Summary) -> some View {
        if let status = summary.status {
            card {
                Label {
                    Text(status.text).fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: status.severity == .notice ? "info.circle" : "exclamationmark.triangle")
                        .foregroundStyle(status.severity == .error ? theme.danger
                                         : (status.severity == .warning ? theme.warning : theme.link))
                }
                if status.joinAgain {
                    field(Words.password) { SecureField(Words.password, text: $model.password).glassField() }
                    HStack {
                        Spacer()
                        Button(SyncWording.joinAgainAction) { Task { if await model.rejoin() { onChange() } } }
                            .buttonStyle(PillButtonStyle(primary: true))
                            .disabled(model.password.isEmpty || model.busy)
                    }
                }
            }
        }
    }

    private var folderRow: some View {
        HStack {
            Text(model.picked?.name ?? Words.noFolder)
                .foregroundStyle(model.picked == nil ? theme.textMuted : theme.text).lineLimit(1)
            Spacer()
            Button(Words.chooseFolder) { pickFolder() }.buttonStyle(GlassButtonStyle())
        }
    }

    private func pickFolder() {
        guard let url = chooseFolder() else { return }
        do {
            model.pick(bookmark: try model.sync.deps.folders.bookmark(for: url), name: url.lastPathComponent)
        } catch {
            model.pickFailed()
        }
    }

    private func heading(_ text: String) -> some View {
        Text(text).font(.system(size: 12)).foregroundStyle(theme.textFaint).accessibilityAddTraits(.isHeader)
    }

    private func field<Control: View>(_ label: String, @ViewBuilder _ control: () -> Control) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label).font(.system(size: 13)).foregroundStyle(theme.textMuted).frame(width: 150, alignment: .leading)
            control()
        }
    }

    private func card<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 10) { content() }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(theme.card, in: RoundedRectangle(cornerRadius: MacTheme.radiusGroup, style: .continuous))
    }

    /// Remove a person: a new share password twice (they know the current one), then a confirmation naming them. The
    /// sheet closes only once the removal worked; a refusal stays here with its reason.
    private func removeSheet(_ member: CollectionShareModel.Member) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(CollectionShareModel.removeButton(member.name)).font(.system(size: 15, weight: .semibold))
            Text(CollectionShareModel.removeHint(member.name)).font(.system(size: 12.5)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            SecureField(Words.newPassword, text: $model.newPassword).glassField()
            SecureField(Words.newPasswordAgain, text: $model.newPasswordAgain).glassField()
            if let error = model.error {
                Text(error).font(.system(size: 12.5)).foregroundStyle(theme.danger).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { removing = nil }.keyboardShortcut(.cancelAction)
                Button(CollectionShareModel.removeButton(member.name)) { confirmingRemove = true }
                    .disabled(model.newPassword.isEmpty || model.newPasswordAgain.isEmpty || model.busy)
            }
        }
        .padding(20).frame(width: 420)
        .foregroundStyle(theme.text)
        .alert(CollectionShareModel.removeTitle(member.name), isPresented: $confirmingRemove) {
            Button(Words.remove, role: .destructive) {
                let id = member.id
                Task {
                    guard await model.remove(id) else { return }
                    removing = nil
                    onChange()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(CollectionShareModel.removeText(person: member.name,
                                                 collection: SyncWording.sanitize(model.summary?.collectionName ?? "")))
        }
    }
}
