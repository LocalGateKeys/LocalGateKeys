import AppKit
import SwiftUI
import AuthenticationServices
import AppSharedMac

/// The Mac credential provider: unlocks with the Touch ID item the app stored, or the master password (the
/// app's shared throttle), reads the app-group store, and fills a password or a one-time code or signs in
/// with a passkey. Its only write is a new passkey (one commit); it never syncs, opens no network connection
/// and never uses the clipboard.
final class CredentialProviderViewController: ASCredentialProviderViewController, MacAutoFillSink {
    private lazy var model: MacAutoFillModel = {
        let directory = (try? AppGroup.vaultDirectory()) ?? FileManager.default.temporaryDirectory
        // The shared Keychain group, given explicitly: the Touch ID item and the vault's local key live there.
        let group = AppGroup.keychainAccessGroup
        let opener = ExtensionVaultOpener(directory: directory,
                                          biometric: SystemBiometricKeyStore(accessGroup: group),
                                          keychain: SystemKeychainVault(accessGroup: group))
        let matcher = AutoFillMatcher.bundled()
        let codes: Bool = if #available(macOS 15.0, *) { true } else { false }
        let m = MacAutoFillModel(opener: opener, matcher: matcher, pro: StoreKitEntitlement(),
                                 identities: IdentityStoreSync(matcher: matcher.matcher, oneTimeCodes: codes))
        m.sink = self
        return m
    }()

    override func loadView() {
        let host = NSHostingView(rootView: AutoFillRootView(model: model))
        host.frame = NSRect(x: 0, y: 0, width: 420, height: 440)
        view = host
    }

    override func viewWillDisappear() {
        super.viewWillDisappear()
        model.dismissed()
    }

    deinit {
        // Backup for viewWillDisappear: the model goes with the controller, its snapshot with it.
        AutoFillTrace.log("autofillmac.deinit")
    }

    // MARK: Entry points (delivered on any thread; the work hops to the main actor)

    override nonisolated func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let urls = AutoFillMatcher.candidateURLs(serviceIdentifiers)
        Self.onMain(self) { $0.model.begin(.list(urls: urls)) }
    }

    override nonisolated func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                                    requestParameters: ASPasskeyCredentialRequestParameters) {
        let urls = AutoFillMatcher.candidateURLs(serviceIdentifiers)
        let rpID = requestParameters.relyingPartyIdentifier, allowed = requestParameters.allowedCredentials
        let hash = requestParameters.clientDataHash
        Self.onMain(self) { $0.model.begin(.passkeyList(urls: urls, rpID: rpID, allowed: allowed, clientDataHash: hash)) }
    }

    @available(macOS 15.0, *)
    override nonisolated func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let urls = AutoFillMatcher.candidateURLs(serviceIdentifiers)
        Self.onMain(self) { $0.model.begin(.oneTimeCodeList(urls: urls)) }
    }

    /// Every request authenticates in the extension's UI: never filled without interaction.
    override nonisolated func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        Self.onMain(self) { vc in
            vc.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                                 code: ASExtensionError.userInteractionRequired.rawValue))
        }
    }

    override nonisolated func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        let route = MacAutoFillRequest.of(credentialRequest)
        Self.onMain(self) { $0.model.begin(route) }
    }

    /// Passkey creation: unlock, confirm site and account, then one commit. With "Offer passkeys" off, a
    /// non-ES256 site, or a full free vault without Pro, the system falls back (`.failed`).
    override nonisolated func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        let route = MacAutoFillRequest.registration(registrationRequest)
        Self.onMain(self) { $0.model.begin(route) }
    }

    /// No-UI conditional registration: declined (the header treats any error alike; no UI may show).
    @available(macOS 15.0, *)
    override nonisolated func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        Self.onMain(self) { $0.cancelRequest(.failed) }
    }

    // MARK: MacAutoFillSink

    /// Text insertion is iOS-only (the macOS SDK marks it unavailable), so the Mac never offers it.
    func completeText(_ text: String) {
        cancelRequest(.failed)
    }

    func completePassword(user: String, password: String) {
        extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password),
                                         completionHandler: nil)
    }

    func completeOneTimeCode(_ code: String) {
        if #available(macOS 15.0, *) {
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code), completionHandler: nil)
        } else {
            cancelRequest(.failed)
        }
    }

    func completePasskey(_ a: PasskeyAssertion) {
        let credential = ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: a.rpID, signature: a.signature,
                                                      clientDataHash: a.clientDataHash, authenticatorData: a.authenticatorData,
                                                      credentialID: a.credentialID)
        extensionContext.completeAssertionRequest(using: credential)
    }

    func completeRegistration(_ r: PasskeyRegistration) {
        let credential = ASPasskeyRegistrationCredential(relyingParty: r.rpID, clientDataHash: r.clientDataHash,
                                                         credentialID: r.credentialID, attestationObject: r.attestationObject)
        extensionContext.completeRegistrationRequest(using: credential)
    }

    func cancelRequest(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    private nonisolated static func onMain(_ vc: CredentialProviderViewController,
                                           _ body: @escaping @MainActor @Sendable (CredentialProviderViewController) -> Void) {
        nonisolated(unsafe) let vc = vc
        if Thread.isMainThread { MainActor.assumeIsolated { body(vc) } }
        else { DispatchQueue.main.async { MainActor.assumeIsolated { body(vc) } } }
    }
}

/// Unlock, list or strict prompt, on the aurora; the app's appearance choice applies.
struct AutoFillRootView: View {
    let model: MacAutoFillModel

    var body: some View {
        content
            .frame(minWidth: 360, minHeight: 300)
            .lgkAuroraBackground()
            .preferredColorScheme(Self.scheme(AppSettings.shared.appearance))
    }

    @ViewBuilder private var content: some View {
        switch model.screen {
        case .idle, .finished: ProgressView().controlSize(.small)
        case .unlock: AutoFillUnlockView(model: model)
        case .list: CredentialListView(model: model)
        case .createPasskey(let rpID, let userName):
            PasskeyCreateSheet(rpID: rpID, userName: userName,
                               create: { Task { await model.createPasskey() } }, cancel: { model.cancel() })
                .frame(width: 420, height: 440)
        case .strict(let row):
            AutoFillPasswordPrompt(
                title: String(localized: "Master password required"),
                detail: row.login.title.isEmpty ? String(localized: "This login needs your master password to fill.")
                    : String(localized: "\(row.login.title) needs your master password to fill."),
                touchID: false, message: model.message, busy: model.busy,
                onTouchID: {}, onSubmit: { p in Task { await model.confirmStrict(password: p) } },
                onCancel: { model.cancelStrict() })
        }
    }

    static func scheme(_ a: Appearance) -> ColorScheme? {
        switch a {
        case .light: return .light
        case .dark: return .dark
        default: return nil
        }
    }
}
