import SwiftUI
import AppKit
import AppSharedMac

/// The detail panel (approved mockup `.det`): header with logo, title, kind · updated, the ☆ favourite toggle,
/// Edit and Open website; then Sign-in (username, password with Show, the live one-time code when the item
/// has one), Website and Notes for logins, or the item's fields for other kinds. Copy buttons say "Copied".
struct DetailPanel: View {
    let item: VaultItem
    let clipboard: MacClipboard
    /// Strict logins ask for the master password before any secret leaves the panel.
    let gate: StrictItemGate
    let onToggleFavourite: () -> Void
    let onCopied: (String) -> Void
    /// Switches the panel into edit mode; nil for kinds the Mac does not edit.
    let onEdit: (() -> Void)?
    /// Asks "Move to Recently deleted?"; nil while editing or without local data.
    let onDelete: (() -> Void)?
    /// Typed items get the Reminder section (Windows: never logins); nil without local data.
    let reminders: RemindersModel?
    /// Recovery codes, custom fields and password history of logins (nil hides those sections).
    let extras: LoginExtrasModel?
    let store: (any ItemStore)?
    /// The extras were saved (reload the list).
    let onExtrasSaved: () -> Void
    /// Recovery codes, hidden values or a previous password were shown (content-free event).
    let onRevealed: () -> Void
    /// Names of the known collections a typed item is in.
    let collectionNames: [String]
    /// Share… (UX workstream 9); nil hides the button (passkeys, attached files).
    let onShare: (() -> Void)?
    @State private var model: ItemDetailModel
    /// A strict login's code and notes stay hidden until "Show" is confirmed.
    @State private var codeShown = false
    @State private var notesShown = false
    @Environment(\.macTheme) private var theme

    init(item: VaultItem, clipboard: MacClipboard, gate: StrictItemGate, onToggleFavourite: @escaping () -> Void, onCopied: @escaping (String) -> Void,
         onEdit: (() -> Void)? = nil, onDelete: (() -> Void)? = nil, reminders: RemindersModel? = nil,
         extras: LoginExtrasModel? = nil, store: (any ItemStore)? = nil,
         onExtrasSaved: @escaping () -> Void = {}, onRevealed: @escaping () -> Void = {}, collectionNames: [String] = [],
         onShare: (() -> Void)? = nil) {
        self.collectionNames = collectionNames; self.onShare = onShare
        self.extras = extras; self.store = store; self.onExtrasSaved = onExtrasSaved; self.onRevealed = onRevealed
        self.onEdit = onEdit; self.onDelete = onDelete; self.reminders = reminders
        self.item = item; self.clipboard = clipboard; self.gate = gate
        self.onToggleFavourite = onToggleFavourite; self.onCopied = onCopied
        _model = State(initialValue: ItemDetailModel(item: item, clipboard: clipboard, clock: SystemClock(),
                                                     concealSecrets: Self.concealsSecrets(item, setting: AppSettings.shared.concealSecretsInDetail)))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                header.padding(.bottom, 2)
                if item.isLogin { loginSections } else { otherSections }
                if !item.tags.isEmpty || !collectionNames.isEmpty { organised }
                if let reminders, RemindersModel.canHaveReminder(item) { ReminderSection(item: item, model: reminders) }
                if let onDelete {
                    HStack {
                        Spacer()
                        Button("Delete", action: onDelete)
                            .buttonStyle(PillButtonStyle(primary: false)).foregroundStyle(theme.danger)
                            .help("Move to Recently deleted (⌫)")
                    }
                    .padding(.top, 18)
                }
            }
            .padding(.horizontal, 18).padding(.vertical, 16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .scrollIndicators(.automatic)
        .softBottomEdge()
        .foregroundStyle(theme.text)
        .font(.system(size: 14))
        .onAppear { extras?.select(item.id) }
        .onChange(of: item.id) { _, id in extras?.select(id) }
        .task(id: item.id) {
            while !Task.isCancelled {
                model.tick()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    // MARK: header

    /// Buttons beside the title when everything fits on one line, else below it: the subtitle never truncates.
    private var header: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                titleBlock.fixedSize(horizontal: true, vertical: false)
                Spacer(minLength: 8)
                headerButtons
            }
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 12) { titleBlock; Spacer(minLength: 8) }
                HStack(spacing: 12) { Spacer(minLength: 0); headerButtons }
            }
        }
    }

    private var titleBlock: some View {
        HStack(spacing: 12) {
            ItemLogo(item: item, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title.isEmpty ? item.kindLabel : item.title)
                    .font(.system(size: 18, weight: .semibold)).lineLimit(1)
                Text(Self.subtitle(item)).font(.system(size: 13)).foregroundStyle(theme.textMuted).lineLimit(1)
            }
        }
    }

    @ViewBuilder private var headerButtons: some View {
        Button(action: onToggleFavourite) {
            Image(systemName: item.favorite ? "star.fill" : "star")
                .font(.system(size: 15)).foregroundStyle(Color.rgb(230, 184, 74))
                .frame(width: 26, height: 26).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(item.favorite ? String(localized: "Remove from Favourites") : String(localized: "Add to Favourites"))
        .accessibilityLabel(item.favorite ? String(localized: "Remove from Favourites") : String(localized: "Add to Favourites"))
        Button("Edit") { onEdit?() }
            .buttonStyle(PillButtonStyle(primary: false))
            .disabled(onEdit == nil)
            .help(onEdit == nil ? String(localized: "Edit this item on your PC.") : String(localized: "Edit this item (⌘E)"))
        if let onShare {
            Button("Share…", action: onShare)
                .buttonStyle(PillButtonStyle(primary: false))
                .help("Share this item with another LocalGateKeys user, sealed with a six-word code")
        }
        if let url = ItemActions.website(item) {
            Button("Open website") { NSWorkspace.shared.open(url) }
                .buttonStyle(PillButtonStyle(primary: true))
        }
    }

    /// A login's password always starts masked on the Mac (showing it needs the routine re-authentication);
    /// the Settings choice applies to other kinds.
    static func concealsSecrets(_ item: VaultItem, setting: Bool) -> Bool { item.isLogin || setting }

    /// "Website login · updated 10 days ago".
    static func subtitle(_ item: VaultItem, now: Date = Date()) -> String {
        guard item.updatedAt > 0 else { return item.kindLabel }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        let when = Date(timeIntervalSince1970: TimeInterval(item.updatedAt))
        let ago = now.timeIntervalSince(when) < 60 ? String(localized: "just now") : f.localizedString(for: when, relativeTo: now)
        return String(localized: "\(item.kindLabel) · updated \(ago)")
    }

    /// Tags (searchable with `tag:`) and collections, as chips.
    private var organised: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !item.tags.isEmpty { chipRow(String(localized: "Tags"), item.tags.map { "#" + VaultItem.safeDisplay($0) }) }
            if !collectionNames.isEmpty { chipRow(String(localized: "Collections"), collectionNames.map { VaultItem.safeDisplay($0) }) }
        }
        .padding(.top, 14)
    }

    private func chipRow(_ title: String, _ chips: [String]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 12)).foregroundStyle(theme.textFaint).accessibilityAddTraits(.isHeader)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 6) { chipViews(chips) }
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 120), spacing: 6, alignment: .leading)], alignment: .leading, spacing: 6) {
                    chipViews(chips)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private func chipViews(_ chips: [String]) -> some View {
            Group {
                ForEach(Array(chips.enumerated()), id: \.offset) { _, chip in
                    Text(chip).font(.system(size: 12.5)).lineLimit(1)
                        .padding(.horizontal, 9).padding(.vertical, 3)
                        .background(theme.chip, in: Capsule()).fixedSize()
                }
            }
    }

    // MARK: logins

    @ViewBuilder private var loginSections: some View {
        let fields = Dictionary(model.fields.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        if fields["username"] != nil || fields["password"] != nil || model.totp != nil {
            SectionLabel(String(localized: "Sign-in"))
            if let f = fields["username"] { fieldRow(f) }
            if let f = fields["password"] { fieldRow(f) }
            if let totp = model.totp { codeRow(totp) }
        }
        if let f = fields["target"] {
            SectionLabel(item.kind == "web" ? String(localized: "Website") : String(localized: "Application"))
            if item.kind == "web", let url = ItemActions.website(item) {
                Button { NSWorkspace.shared.open(url) } label: {
                    Text(f.value).foregroundStyle(theme.link).lineLimit(1).truncationMode(.middle)
                }
                .buttonStyle(.plain).padding(.vertical, 6)
                .help("Open website")
            } else {
                Text(f.value).textSelection(.enabled).padding(.vertical, 6)
            }
        }
        SectionLabel(String(localized: "Notes"))
        if let f = fields["notes"], strict, !notesShown {
            HStack(spacing: 12) {
                Text("Hidden").foregroundStyle(theme.textMuted)
                Button("Show") { gate.release(item, action: String(localized: "Show notes")) { notesShown = true } }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
                    .accessibilityLabel(String(localized: "Show \(EditorKind.midSentence(f.label))"))
            }
            .padding(.vertical, 6)
        } else if let f = fields["notes"] {
            Text(f.value).textSelection(.enabled).padding(.vertical, 6)
        } else {
            Text("No notes").foregroundStyle(theme.textMuted).padding(.vertical, 6)
        }
        if let extras {
            LoginExtrasSections(item: item, model: extras, gate: gate, clipboard: clipboard, store: store,
                                onCopied: onCopied, onSaved: onExtrasSaved, onRevealed: onRevealed)
        }
    }

    // MARK: other kinds

    @ViewBuilder private var otherSections: some View {
        let notes = model.fields.first { $0.id == "notes" || $0.id == "body" }
        let rest = model.fields.filter { $0.id != notes?.id }
        if item.kind == AttachmentDocuments.kind, let store {
            DocumentFileSection(item: item, store: store, gate: gate, onChanged: onExtrasSaved)
        }
        if !rest.isEmpty || model.totp != nil {
            SectionLabel(String(localized: "Details"))
            ForEach(rest) { fieldRow($0) }
            if let totp = model.totp { codeRow(totp) }
        }
        if let notes {
            SectionLabel(notes.label == "Body" ? String(localized: "Notes") : notes.label)
            Text(notes.value).textSelection(.enabled).padding(.vertical, 6)
        }
        if model.fields.isEmpty && model.totp == nil && item.kind != AttachmentDocuments.kind {
            Text("Nothing saved in this item yet.").foregroundStyle(theme.textMuted).padding(.vertical, 14)
        }
    }

    private var strict: Bool { StrictItemGate.isStrict(item) }

    // MARK: rows

    private func fieldRow(_ field: DetailField) -> some View {
        let masked = field.isSecret && !model.isRevealed(field)
        return KeyValueRow(label: field.label) {
            if masked {
                Text(model.displayValue(field)).font(.system(size: 14, design: .monospaced)).lineLimit(1)
            } else {
                // A strict login's values leave only through the gated copy buttons.
                if strict {
                    Text(field.value).textSelection(.disabled)
                        .lineLimit(field.isMultiline ? nil : 1).truncationMode(.middle)
                } else {
                    Text(field.value).textSelection(.enabled)
                        .lineLimit(field.isMultiline ? nil : 1).truncationMode(.middle)
                }
            }
        } actions: {
            if field.isSecret {
                Button(model.isRevealed(field) ? String(localized: "Hide") : String(localized: "Show")) {
                    if model.isRevealed(field) { model.toggleReveal(field) }
                    else { release(field, String(localized: "Show \(EditorKind.midSentence(field.label))")) { model.toggleReveal(field) } }
                }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
            }
            CopyButton(label: field.label) {
                release(field, String(localized: "Copy \(EditorKind.midSentence(field.label))")) {
                    clipboard.copy(field.value, concealed: field.isSecret)
                    onCopied(field.label)
                }
            }
        }
    }

    /// The password asks for routine re-authentication (Windows `field == "password" or strict`); the rest only
    /// on strict logins.
    private func release(_ field: DetailField, _ action: String, perform: @escaping () -> Void) {
        if item.isLogin && field.id == "password" { gate.releaseRoutine(item, action: action, perform: perform) }
        else { gate.release(item, action: action, perform: perform) }
    }

    private func codeRow(_ totp: TOTPState) -> some View {
        KeyValueRow(label: String(localized: "One-time code")) {
            if strict && !codeShown {
                Text("Hidden").foregroundStyle(theme.textMuted)
            } else {
                HStack(spacing: 10) {
                    Text(Self.grouped(totp.code))
                        .font(.system(size: 17, weight: .semibold, design: .monospaced)).tracking(1)
                    CodeRing(fraction: totp.fractionRemaining, seconds: totp.secondsRemaining)
                }
            }
        } actions: {
            if strict && !codeShown {
                Button("Show") { gate.release(item, action: String(localized: "Show one-time code")) { codeShown = true } }
                    .buttonStyle(.plain).foregroundStyle(theme.link)
            }
            CopyButton(label: String(localized: "One-time code")) {
                gate.release(item, action: String(localized: "Copy one-time code")) {
                    // The code current when the password is confirmed.
                    clipboard.copy(model.totp?.code ?? totp.code, concealed: true)
                    onCopied(String(localized: "Code"))
                }
            }
        }
    }

    /// "123 456".
    static func grouped(_ code: String) -> String {
        guard code.count == 6 || code.count == 8 else { return code }
        let mid = code.index(code.startIndex, offsetBy: code.count / 2)
        return code[..<mid] + " " + code[mid...]
    }
}

/// Mockup `.lab`: the faint small section label.
struct SectionLabel: View {
    let title: String
    @Environment(\.macTheme) private var theme
    init(_ title: String) { self.title = title }
    var body: some View {
        Text(title).font(.system(size: 12)).foregroundStyle(theme.textFaint)
            .padding(.top, 14).padding(.bottom, 4)
            .accessibilityAddTraits(.isHeader)
    }
}

/// Mockup `.kv`: label column of 120 pt, the value, the actions on the right.
struct KeyValueRow<Value: View, Actions: View>: View {
    let label: String
    @ViewBuilder var value: Value
    @ViewBuilder var actions: Actions
    @Environment(\.macTheme) private var theme

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            Text(label).font(.system(size: 13)).foregroundStyle(theme.textMuted)
                .frame(width: 120, alignment: .leading).lineLimit(1)
            value.frame(maxWidth: .infinity, alignment: .leading)
            HStack(spacing: 12) { actions }
        }
        .padding(.vertical, 10)
    }
}

/// The ⧉ copy button.
struct CopyButton: View {
    let label: String
    let action: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        Button(action: action) {
            Image(systemName: "doc.on.doc").font(.system(size: 13)).foregroundStyle(theme.link)
                .frame(width: 22, height: 22).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(String(localized: "Copy \(EditorKind.midSentence(label))"))
        .accessibilityLabel(String(localized: "Copy \(EditorKind.midSentence(label))"))
    }
}

/// The seconds left in the code's period, as a small ring.
private struct CodeRing: View {
    let fraction: Double
    let seconds: Int
    @Environment(\.macTheme) private var theme

    var body: some View {
        ZStack {
            Circle().stroke(theme.line, lineWidth: 2.5)
            Circle().trim(from: 0, to: fraction)
                .stroke(seconds <= 5 ? theme.warning : theme.live, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Text("\(seconds)").font(.system(size: 9, weight: .medium).monospacedDigit()).foregroundStyle(theme.textMuted)
        }
        .frame(width: 20, height: 20)
        .accessibilityLabel("\(seconds) seconds left")
    }
}

/// The "Copied" toast at the bottom of the window.
struct CopiedToast: View {
    let text: String
    @Environment(\.macTheme) private var theme

    var body: some View {
        Text(text)
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(theme.text)
            .padding(.horizontal, 14).padding(.vertical, 7)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().strokeBorder(theme.panelBorder))
            .shadow(color: .black.opacity(0.15), radius: 8, y: 2)
            .accessibilityAddTraits(.updatesFrequently)
    }
}
