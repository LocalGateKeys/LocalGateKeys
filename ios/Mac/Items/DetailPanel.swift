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
    /// "Set expiry from token" (API keys): writes `expires` (`yyyy-MM-dd`) through the editor's save; nil hides the button.
    let onSetExpiry: ((String) -> SaveResult)?
    /// In a collection shared with this vault as view only (sub-plan 07): it says so, and the star is off (the window
    /// also passes no Edit, Delete or Set expiry).
    let readOnly: Bool
    /// Feature pack §4.4: setting or tightening access rules needs Pro (`onNeedsPro` shows the upgrade prompt).
    let pro: Bool
    let onNeedsPro: () -> Void
    /// Item history (feature pack §1); nil hides the section.
    let history: MacItemHistoryModel?
    /// This Mac's local data (the passkey upgrade card's "Not now", feature pack §6.3); nil hides the card.
    let local: (any LocalDataHosting)?
    @State private var model: ItemDetailModel
    /// A strict login's code and notes stay hidden until "Show" is confirmed.
    @State private var codeShown = false
    @State private var notesShown = false
    /// The Wi-Fi QR popover (after the password was revealed).
    @State private var wifiQRShown = false
    /// "Set expiry from token" could not be saved.
    @State private var tokenExpiryFailed = false
    /// The expiry was written: the stored item is reloaded by the list, this panel keeps its model, so hide the button.
    @State private var tokenExpirySet = false
    /// The per-device "Show formatting" switch under a note (Markdown, default on).
    @AppStorage(NoteFormatting.settingKey) private var showFormatting = true
    @Environment(\.macTheme) private var theme

    init(item: VaultItem, clipboard: MacClipboard, gate: StrictItemGate, onToggleFavourite: @escaping () -> Void, onCopied: @escaping (String) -> Void,
         onEdit: (() -> Void)? = nil, onDelete: (() -> Void)? = nil, reminders: RemindersModel? = nil,
         extras: LoginExtrasModel? = nil, store: (any ItemStore)? = nil,
         onExtrasSaved: @escaping () -> Void = {}, onRevealed: @escaping () -> Void = {}, collectionNames: [String] = [],
         onShare: (() -> Void)? = nil, onSetExpiry: ((String) -> SaveResult)? = nil, readOnly: Bool = false,
         pro: Bool = false, onNeedsPro: @escaping () -> Void = {}, history: MacItemHistoryModel? = nil,
         local: (any LocalDataHosting)? = nil) {
        self.pro = pro; self.onNeedsPro = onNeedsPro; self.history = history; self.local = local
        self.collectionNames = collectionNames; self.onShare = onShare; self.onSetExpiry = onSetExpiry; self.readOnly = readOnly
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
                if readOnly {
                    Label(EditorModel.readOnlyItemText, systemImage: "lock")
                        .font(.system(size: 13)).foregroundStyle(theme.textMuted).padding(.top, 8)
                        .fixedSize(horizontal: false, vertical: true)
                }
                accessBanner
                if item.kind == "web", !readOnly, let store, let local {
                    MacPasskeyUpgradeCard(item: item, store: store, local: local)
                }
                if item.isLogin { loginSections } else { otherSections }
                if !item.tags.isEmpty || !collectionNames.isEmpty { organised }
                if let reminders, RemindersModel.canHaveReminder(item) { ReminderSection(item: item, model: reminders) }
                if let history { ItemHistorySection(item: item, model: history, gate: gate, readOnly: readOnly, onRestored: onExtrasSaved) }
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
        // Hiding the password (or anything that drops the reveal) closes the QR popover.
        .onChange(of: model.wifiQRText) { _, text in if text == nil { wifiQRShown = false } }
        .alert("Couldn't set the expiry.", isPresented: $tokenExpiryFailed) { Button("OK") {} }
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
        .disabled(readOnly)
        .help(item.favorite ? String(localized: "Remove from Favourites") : String(localized: "Add to Favourites"))
        .accessibilityLabel(item.favorite ? String(localized: "Remove from Favourites") : String(localized: "Add to Favourites"))
        Button("Edit") { onEdit?() }
            .buttonStyle(PillButtonStyle(primary: false))
            .disabled(onEdit == nil)
            .help(readOnly ? EditorModel.readOnlyItemText
                  : (onEdit == nil ? String(localized: "detail.edit.unavailable", defaultValue: "This kind of item can't be edited on this Mac yet.")
                                   : String(localized: "Edit this item (⌘E)")))
        // Share and Move to Recently deleted sit in the menu beside Edit (UX refresh 2026-11-12).
        if onShare != nil || onDelete != nil {
            Menu {
                if let onShare {
                    Button(String(localized: "Share…"), action: onShare)
                }
                if let onDelete {
                    Button(String(localized: "Move to Recently deleted"), role: .destructive, action: onDelete)
                }
            } label: {
                Image(systemName: "ellipsis.circle").font(.system(size: 15))
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .foregroundStyle(theme.textMuted)
            .help(String(localized: "detail.more", defaultValue: "More actions"))
            .accessibilityLabel(String(localized: "detail.more", defaultValue: "More actions"))
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
            if !collectionNames.isEmpty { chipRow(String(localized: "Collections"), collectionNames.map { VaultItem.safeDisplay(CollectionCatalog.displayName($0)) }) }
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
        // Windows order: the live code first, under the header; then username, password and website together.
        if let totp = model.totp {
            SectionLabel(String(localized: "One-time code"))
            codeRow(totp)
        }
        if fields["username"] != nil || fields["password"] != nil || fields["target"] != nil {
            SectionLabel(String(localized: "Sign-in"))
            if let f = fields["username"] { fieldRow(f) }
            if let f = fields["password"] { fieldRow(f) }
            if let f = fields["target"] {
                KeyValueRow(label: item.kind == "web" ? String(localized: "Website") : String(localized: "Application")) {
                    if item.kind == "web", let url = ItemActions.website(item) {
                        Button { NSWorkspace.shared.open(url) } label: {
                            Text(f.value).foregroundStyle(theme.link).lineLimit(1).truncationMode(.middle)
                        }
                        .buttonStyle(.plain).help("Open website")
                    } else {
                        Text(f.value).textSelection(.enabled).lineLimit(1).truncationMode(.middle)
                    }
                } actions: {
                    CopyButton(label: item.kind == "web" ? String(localized: "Website") : String(localized: "Application")) {
                        clipboard.copy(f.value, concealed: false)
                        onCopied(item.kind == "web" ? String(localized: "Website") : String(localized: "Application"))
                    }
                }
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
            noteBody(f)
        } else {
            Text("No notes").foregroundStyle(theme.textMuted).padding(.vertical, 6)
        }
        if let store, !readOnly {
            AutofillRulesSection(item: item, store: store, gate: gate, onSaved: onExtrasSaved)
            if item.kind == "web" {
                AccessRulesSection(item: item, store: store, gate: gate, pro: pro, onNeedsPro: onNeedsPro, onSaved: onExtrasSaved)
            }
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
        ForEach(rest) { field in
            if let info = model.token(for: field) { tokenSection(info, field: field) }
        }
        if item.kind == "wifi" { wifiQRRow }
        if let notes {
            SectionLabel(notes.label == "Body" ? String(localized: "Notes") : notes.label)
            noteBody(notes)
        }
        if model.fields.isEmpty && model.totp == nil && item.kind != AttachmentDocuments.kind {
            Text("Nothing saved in this item yet.").foregroundStyle(theme.textMuted).padding(.vertical, 14)
        }
    }

    /// The decoded token of a revealed API-key value: read-only, signature not checked.
    @ViewBuilder private func tokenSection(_ info: JWTInfo, field: DetailField) -> some View {
        let both = model.fields.filter { model.token(for: $0) != nil }.count > 1
        SectionLabel(both ? "\(String(localized: "Token")) · \(field.label)" : String(localized: "Token"))
        ForEach(model.tokenRows(info)) { row in
            KeyValueRow(label: row.label) {
                HStack(spacing: 8) {
                    Text(row.value).textSelection(.enabled)
                    if row.expired { Text("Expired").font(.system(size: 12, weight: .semibold)).foregroundStyle(theme.danger) }
                }
            } actions: {}
        }
        Text("Signature not checked").font(.system(size: 12)).foregroundStyle(theme.textMuted).padding(.top, 6)
        if let onSetExpiry, !tokenExpirySet, model.canSetExpiry(from: info), let date = ItemDetailModel.expiryDate(info) {
            HStack {
                Button("Set expiry from token") {
                    switch onSetExpiry(date) {
                    case .saved, .unchanged: tokenExpirySet = true
                    default: tokenExpiryFailed = true
                    }
                }
                .buttonStyle(PillButtonStyle(primary: false))
                Spacer(minLength: 0)
            }
            .padding(.top, 8)
        }
    }

    /// Show QR for a Wi-Fi network: revealing the password (with its re-authentication) is the permission;
    /// enterprise types have no QR.
    @ViewBuilder private var wifiQRRow: some View {
        if model.offersWifiQR {
            HStack {
                Button("Show QR", action: showWifiQR)
                    .buttonStyle(PillButtonStyle(primary: false))
                    .popover(isPresented: $wifiQRShown, arrowEdge: .bottom) {
                        if let text = model.wifiQRText { WifiQRPopover(text: text) }
                    }
                Spacer(minLength: 0)
            }
            .padding(.top, 10)
        } else {
            Text("Enterprise networks can't be shared with a QR code.")
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).padding(.top, 10)
        }
    }

    private func showWifiQR() {
        Self.requestWifiQR(model: model, item: item, gate: gate) { wifiQRShown = $0 }
    }

    /// The password is revealed through the gate (strict items ask for the master password first), then
    /// `completion(true)` says the QR may be shown. Until the gate runs its action `wifiQRText` stays nil.
    static func requestWifiQR(model: ItemDetailModel, item: VaultItem, gate: StrictItemGate,
                              completion: @escaping (Bool) -> Void) {
        guard let pw = model.wifiPasswordField, !model.isRevealed(pw) else { completion(model.wifiQRText != nil); return }
        gate.release(item, action: String(localized: "Show QR")) {
            model.toggleReveal(pw)
            completion(model.wifiQRText != nil)
        }
    }

    private var strict: Bool { StrictItemGate.isStrict(item) }
    /// Feature pack §4: the item's access rules on this Mac.
    private var rules: AccessRules.Effective { MacAccess.rules(item.record) }

    /// An expired rule or one from a newer version (§4.2): says that every use asks for the master password.
    @ViewBuilder private var accessBanner: some View {
        if item.isLogin, let text = MacAccess.banner(rules) {
            Label(text, systemImage: rules.unknownRule ? "lock.shield" : "clock.badge.exclamationmark")
                .font(.system(size: 13)).foregroundStyle(theme.textMuted).padding(.top, 8)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityElement(children: .combine)
        }
    }

    /// A note's text (only called once it may be shown): Markdown when the switch under it is on, else plain.
    @ViewBuilder private func noteBody(_ field: DetailField) -> some View {
        let isNote = NoteFormatting.formats(kind: item.kind, fieldId: field.id)
        VStack(alignment: .leading, spacing: 6) {
            if isNote && showFormatting {
                MarkdownNoteView(text: field.value,
                                 colors: MarkdownNoteColors(text: theme.text, secondary: theme.textMuted, accent: theme.link,
                                                            codeBackground: theme.chip),
                                 selectable: true)
            } else {
                Text(field.value).textSelection(.enabled)
            }
            if isNote { ShowFormattingToggle(isOn: $showFormatting).controlSize(.small) }
        }
        .padding(.vertical, 6)
    }

    // MARK: rows

    private func fieldRow(_ field: DetailField) -> some View {
        let masked = field.isSecret && !model.isRevealed(field)
        return KeyValueRow(label: field.label) {
            if masked {
                Text(model.displayValue(field)).font(.system(size: 14, design: .monospaced)).lineLimit(1)
            } else {
                // A strict or copy-once login's values leave only through the gated copy buttons.
                if strict || rules.copyOnce {
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
                if field.isSecret {
                    // Copy once (feature pack §4.1) counts every secret of the item.
                    gate.releaseCopy(item, action: String(localized: "Copy \(EditorKind.midSentence(field.label))"),
                                     routine: item.isLogin && field.id == "password") { limit in
                        clipboard.copy(field.value, concealed: true, limit: limit)
                        onCopied(field.label)
                    }
                } else {
                    release(field, String(localized: "Copy \(EditorKind.midSentence(field.label))")) {
                        clipboard.copy(field.value, concealed: false)
                        onCopied(field.label)
                    }
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
                gate.releaseCopy(item, action: String(localized: "Copy one-time code")) { limit in
                    // Settings › Locking › Ask before releasing 2FA codes (Windows `totp_confirm`).
                    guard MacTOTPConfirm.allow(title: item.title) else { return }
                    // The code current when the password is confirmed.
                    clipboard.copy(model.totp?.code ?? totp.code, concealed: true, limit: limit)
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
        // UX refresh 2026-11-12: the label above the value, the actions on the value's line.
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.system(size: 12)).foregroundStyle(theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .center, spacing: 10) {
                value.frame(maxWidth: .infinity, alignment: .leading)
                HStack(spacing: 12) { actions }
            }
        }
        .padding(.vertical, 8)
    }
}

/// The ⧉ copy button.
struct CopyButton: View {
    let label: String
    let action: () -> Void
    @Environment(\.macTheme) private var theme

    var body: some View {
        Button(action: action) {
            Label(String(localized: "detail.copy", defaultValue: "Copy"), systemImage: "doc.on.doc")
                .labelStyle(.titleAndIcon)
                .font(.system(size: 12.5)).foregroundStyle(theme.link)
                .fixedSize()
                .frame(minHeight: 22).contentShape(Rectangle())
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

/// The Wi-Fi QR code in a popover. The image is made when it opens and dropped when it closes.
private struct WifiQRPopover: View {
    let text: String
    @State private var image: NSImage?
    @Environment(\.macTheme) private var theme

    var body: some View {
        VStack(spacing: 12) {
            if let image {
                Image(nsImage: image).interpolation(.none).resizable().scaledToFit()
                    .frame(width: 240, height: 240)
                    .accessibilityHidden(true)
            }
            Text("The image contains the Wi-Fi password. Only show it to people you want to connect.")
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Text("This code does not expire: anyone who scans or photographs it keeps the Wi-Fi password. Change the Wi-Fi password to take it back.")
                .font(.system(size: 12)).foregroundStyle(theme.textMuted).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(width: 280)
        .onAppear { image = QRImage.make(text, side: 240) }
        .onDisappear { image = nil }
    }
}
