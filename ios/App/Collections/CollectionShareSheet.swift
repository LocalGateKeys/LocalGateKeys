import SwiftUI
import AppShared

/// Share a collection, or join a shared one (sub-plan 07 task 5h; desktop `CollectionShare.svelte`). With a collection:
/// Share (folder, your name, the password twice, "Members can edit"), or once shared its status (with Join again), the
/// mode, People (Remove with a new password twice), Waiting for approval (Let them in, by name), Removed and Leave /
/// Stop sharing. Without one: Join a shared collection (folder and password); after the join it shows that collection.
/// The free plan gets the upgrade sheet for Share and Join. Password fields are emptied by every action and on close.
struct CollectionShareSheet: View {
    @State private var model: CollectionShareModel
    let pro: ProModel?
    /// After a change: the Collections and Vault lists reload.
    let onChange: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var choosingFolder = false
    @State private var removing: CollectionShareModel.Member?
    @State private var confirmingRemove = false
    @State private var confirmingApprove = false
    @State private var confirmingLeave = false
    @State private var confirmingForget = false

    init(collectionID: String?, sync: SyncCoordinator, pro: ProModel?, onChange: @escaping () -> Void = {}) {
        _model = State(initialValue: CollectionShareModel(collectionID: collectionID, sync: sync))
        self.pro = pro
        self.onChange = onChange
    }

    var body: some View {
        NavigationStack {
            Form {
                if model.collectionID == nil {
                    joinSections
                } else if let summary = model.summary {
                    if summary.shared {
                        sharedSections(summary)
                    } else if let link = summary.linked {
                        linkedSection(link)
                    } else {
                        shareSections(summary)
                    }
                }
                if let message = model.message {
                    Section { Text(message).foregroundStyle(Palette.text) }.listRowBackground(Palette.groupSurface)
                }
                if let error = model.error {
                    Section { Text(error).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
                }
            }
            .disabled(model.busy)
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } }
            }
            .overlay { if model.busy { ProgressView() } }
        }
        .sheet(isPresented: $choosingFolder) {
            FolderPicker(onPick: { url in
                choosingFolder = false
                do {
                    model.pick(bookmark: try model.sync.deps.folders.bookmark(for: url), name: url.lastPathComponent)
                } catch {
                    model.pickFailed()
                }
            }, onCancel: { choosingFolder = false })
        }
        .sheet(item: $removing, onDismiss: { model.clearPasswords() }) { member in removeSheet(member) }
        .sheet(isPresented: $model.showUpgrade) { if let pro { UpgradeView(pro: pro) } }
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
        .onAppear { model.reload() }
        .onDisappear { model.clearPasswords() }
    }

    // MARK: - Shared by another of this person's devices

    /// A received share link (final review finding 4): which role that device has, and Forget share link for a device
    /// that was lost or reset (asks first).
    @ViewBuilder private func linkedSection(_ link: CollectionShares.Link) -> some View {
        Section {
            Button(Words.forgetLink, role: .destructive) { confirmingForget = true }
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text(CollectionShareModel.linkedText(link))
                Text(CollectionShareModel.forgetLinkHintText)
            }
        }
        .listRowBackground(Palette.groupSurface)
    }

    private var title: String {
        guard let summary = model.summary else { return Words.joinTitle }
        return CollectionShareModel.shareTitle(summary.collectionName)
    }

    // MARK: - Join

    @ViewBuilder private var joinSections: some View {
        Section {
            folderRow
            TextField(Words.yourName, text: $model.name, prompt: Text(Words.namePlaceholder))
                .textInputAutocapitalization(.words).autocorrectionDisabled()
            SecureField(Words.password, text: $model.password)
                .textContentType(VaultInputTraits.secretContentType).textInputAutocapitalization(.never).autocorrectionDisabled()
        } footer: {
            Text(CollectionShareModel.joinIntroText)
        }
        .listRowBackground(Palette.groupSurface)
        Section {
            Button(Words.join) { Task { if await model.join() { onChange() } } }
                .disabled(model.picked == nil || model.password.isEmpty)
        }
        .listRowBackground(Palette.groupSurface)
    }

    // MARK: - Share

    @ViewBuilder private func shareSections(_ summary: CollectionShareModel.Summary) -> some View {
        statusSection(summary)
        Section {
            folderRow
            TextField(Words.yourName, text: $model.name, prompt: Text(Words.namePlaceholder))
                .textInputAutocapitalization(.words).autocorrectionDisabled()
            SecureField(Words.password, text: $model.password)
                .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
            SecureField(Words.passwordAgain, text: $model.passwordAgain)
                .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
            Toggle(Words.canEdit, isOn: $model.membersCanEdit)
        } header: {
            Text(CollectionShareModel.introText).textCase(nil)
        } footer: {
            Text(CollectionShareModel.modeFixedText)
        }
        .listRowBackground(Palette.groupSurface)
        Section {
            Button(Words.shareButton) { Task { if await model.share() { onChange() } } }
                .disabled(model.picked == nil || model.password.isEmpty || model.passwordAgain.isEmpty)
        } footer: {
            helpFooter
        }
        .listRowBackground(Palette.groupSurface)
    }

    // MARK: - Shared

    @ViewBuilder private func sharedSections(_ summary: CollectionShareModel.Summary) -> some View {
        if summary.sharedTwice {
            // Shared from two of this person's devices (re-review wave B, B1): one share should be stopped or left.
            Section { Text(CollectionShareModel.sharedTwiceText).foregroundStyle(Palette.danger) }
                .listRowBackground(Palette.groupSurface)
        }
        statusSection(summary)
        Section {
            Text(summary.modeText ?? "").foregroundStyle(Palette.text)
            if !summary.folder.isEmpty {
                LabeledContent(Words.folder, value: summary.folder)
            }
        } footer: {
            Text(CollectionShareModel.modeFixedText)
        }
        .listRowBackground(Palette.groupSurface)
        if summary.canUpgradeShare {
            // The owner of a share v1 collection: upgrade to share v2 with the share password typed twice.
            Section {
                SecureField(Words.password, text: $model.password)
                    .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                SecureField(Words.passwordAgain, text: $model.passwordAgain)
                    .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                Button(Words.upgradeButton) { Task { if await model.upgradeShare() { onChange() } } }
                    .disabled(model.password.isEmpty || model.passwordAgain.isEmpty || model.busy)
            } header: {
                Text(CollectionShareModel.upgradeTitle)
            } footer: {
                Text(CollectionShareModel.upgradeText)
            }
            .listRowBackground(Palette.groupSurface)
        }
        Section(Words.people) {
            ForEach(summary.members) { member in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: member.isSelf ? "\(member.name) (\(Words.you))" : member.name).foregroundStyle(Palette.text)
                        Text(member.stateText).font(.footnote).foregroundStyle(Palette.secondaryText)
                    }
                    Spacer()
                    if member.removable {
                        Button(Words.remove, role: .destructive) { model.clearPasswords(); model.dismissMessages(); removing = member }
                            .buttonStyle(.borderless)
                    }
                }
            }
        }
        .listRowBackground(Palette.groupSurface)
        if !summary.pending.isEmpty {
            Section {
                ForEach(summary.pending) { member in
                    Toggle(member.name, isOn: Binding(
                        get: { model.selectedPending.contains(member.id) },
                        set: { on in if on { model.selectedPending.insert(member.id) } else { model.selectedPending.remove(member.id) } }))
                }
                Button(Words.letIn) { confirmingApprove = true }
                    .disabled(model.approvalNames == nil)
            } header: {
                Text(Words.waiting)
            } footer: {
                Text(CollectionShareModel.waitingHintText)
            }
            .listRowBackground(Palette.groupSurface)
        }
        if !summary.removed.isEmpty {
            Section(Words.removedHeading) {
                ForEach(summary.removed) { removed in
                    HStack {
                        Text(removed.name).foregroundStyle(Palette.text)
                        Spacer()
                        Text(Date(timeIntervalSince1970: TimeInterval(removed.at)), style: .date)
                            .foregroundStyle(Palette.secondaryText)
                    }
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
        Section {
            Button(summary.isOwner ? Words.stopSharing : Words.leave, role: .destructive) { confirmingLeave = true }
        } footer: {
            helpFooter
        }
        .listRowBackground(Palette.groupSurface)
    }

    // MARK: - Parts

    /// The last share run's status; Join again (with the share password) after a lost join.
    @ViewBuilder private func statusSection(_ summary: CollectionShareModel.Summary) -> some View {
        if let status = summary.status {
            Section {
                Label {
                    Text(status.text).foregroundStyle(Palette.text)
                } icon: {
                    Image(systemName: status.severity == .notice ? "info.circle" : "exclamationmark.triangle")
                        .foregroundStyle(status.severity == .error ? Palette.danger
                                         : (status.severity == .warning ? Palette.warning : Palette.accentText))
                }
                .accessibilityElement(children: .combine)
                if status.joinAgain {
                    SecureField(Words.password, text: $model.password)
                        .textContentType(VaultInputTraits.secretContentType).textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button(SyncWording.joinAgainAction) { Task { if await model.rejoin() { onChange() } } }
                        .disabled(model.password.isEmpty)
                }
            }
            .listRowBackground(Palette.groupSurface)
        }
    }

    @ViewBuilder private var folderRow: some View {
        HStack {
            Text(model.picked?.name ?? Words.noFolder)
                .foregroundStyle(model.picked == nil ? Palette.secondaryText : Palette.text)
            Spacer()
            Button(Words.chooseFolder) { choosingFolder = true }.buttonStyle(.borderless)
        }
    }

    private var helpFooter: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(CollectionShareModel.helpText)
            Text(CollectionShareModel.ownerLossText)
        }
    }

    private func removeSheet(_ member: CollectionShareModel.Member) -> some View {
        NavigationStack {
            Form {
                Section {
                    SecureField(Words.newPassword, text: $model.newPassword)
                        .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField(Words.newPasswordAgain, text: $model.newPasswordAgain)
                        .textContentType(.newPassword).textInputAutocapitalization(.never).autocorrectionDisabled()
                } header: {
                    Text(CollectionShareModel.removeHint(member.name)).textCase(nil)
                }
                .listRowBackground(Palette.groupSurface)
                Section {
                    Button(CollectionShareModel.removeButton(member.name), role: .destructive) { confirmingRemove = true }
                        .disabled(model.newPassword.isEmpty || model.newPasswordAgain.isEmpty || model.busy)
                }
                .listRowBackground(Palette.groupSurface)
                // A refusal (weak or reused password, busy...) keeps this sheet open and says why here.
                if let error = model.error {
                    Section { Text(error).foregroundStyle(Palette.danger) }.listRowBackground(Palette.groupSurface)
                }
            }
            .scrollContentBackground(.hidden)
            .lgkAuroraBackground()
            .navigationTitle(CollectionShareModel.removeButton(member.name))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { removing = nil } }
            }
            .alert(CollectionShareModel.removeTitle(member.name), isPresented: $confirmingRemove) {
                Button(Words.remove, role: .destructive) {
                    let id = member.id
                    // The model reads and empties the fields first; the sheet closes only once the removal worked (its
                    // result shows in the Share sheet), a refusal stays here with its reason.
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

    /// The sheet's labels (desktop `collectionShare.*`), shared with the Mac's share page.
    typealias Words = CollectionShareModel.Words
}
