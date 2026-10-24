import UIKit
import SwiftUI
import AuthenticationServices
import LocalAuthentication
import StoreKit
import AppShared

/// The `pro_unlimited` entitlement as StoreKit holds it on the device. `Transaction.currentEntitlements` is
/// local (works offline, in an extension) and never shows an Apple Account sign-in: no products are loaded
/// and `AppStore.sync()` is never called here.
struct StoreKitEntitlement: ProEntitlementChecking {
    func isEntitled() async -> Bool {
        for await result in Transaction.currentEntitlements {
            if case .verified(let t) = result, t.productID == "pro_unlimited", t.revocationDate == nil { return true }
        }
        return false
    }
}

/// Face ID / Touch ID with the device passcode as fallback; the authenticated context opens the
/// Keychain local key without a second prompt.
/// The `LAContext` is created, evaluated and handed to the vault on the main actor and never shared
/// across isolation domains (it is not Sendable); `evaluatePolicy` is the completion-handler API, resumed
/// through a checked continuation carrying only Sendable values.
@MainActor
struct SystemAutoFillAuth: AutoFillAuthenticating {
    func authenticate(reason: String) async throws -> any KeychainVault {
        let ctx = LAContext()
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        #if DEBUG
        var canError: NSError?
        let can = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canError)
        AutoFillTrace.log("auth.canEvaluate=\(can) biometryType=\(ctx.biometryType.rawValue) error=\(error: canError)")
        let started = Date()
        #endif
        AutoFillTrace.log("auth.evaluatePolicy begin")
        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, error in
                    if ok { cont.resume() } else { cont.resume(throwing: error ?? LAError(.authenticationFailed)) }
                }
            }
        } catch {
            #if DEBUG
            AutoFillTrace.log("auth.evaluatePolicy failed after \(Date().timeIntervalSince(started))s error=\(error: error)")
            #endif
            throw error
        }
        #if DEBUG
        AutoFillTrace.log("auth.evaluatePolicy ok after \(Date().timeIntervalSince(started))s")
        #endif
        return SystemKeychainVault(context: ctx)
    }
}

/// The credential provider. It reads the app-group store with the Keychain local key (no Argon2id),
/// never syncs and never opens a network connection. Its only write is a new passkey item (one commit).
final class CredentialProviderViewController: ASCredentialProviderViewController, UITableViewDataSource, UITableViewDelegate,
    CredentialRequestSink {
    private lazy var driver: CredentialRequestDriver = {
        let matcher = AutoFillMatcher.bundled()
        let flow = CredentialFlow(auth: SystemAutoFillAuth(), opener: ExtensionStoreOpener(), matcher: matcher,
                                  clipboard: SecretClipboard.shared, clock: SystemClock())
        let d = CredentialRequestDriver(passkeys: PasskeyFlow(credentials: flow, pro: StoreKitEntitlement(),
                                                              identities: IdentityStoreSync(matcher: matcher.matcher)))
        d.sink = self
        return d
    }()
    private var logins: [AutoFillLogin] = []
    /// Rows of a passkey list (a passkey request shows only passkeys).
    private var passkeyRows: [PasskeyCandidate] = []
    /// The registration confirmation, while shown.
    private var createSheet: UIViewController?
    private let table = UITableView(frame: .zero, style: .insetGrouped)
    private let message = UILabel()

    #if DEBUG
    override init(nibName: String?, bundle: Bundle?) {
        super.init(nibName: nibName, bundle: bundle)
        AutoFillTrace.log("vc.init instance=\(instance: self)")
    }
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        AutoFillTrace.log("vc.init(coder) instance=\(instance: self)")
    }
    deinit { AutoFillTrace.log("vc.deinit") }

    private func traceView(_ step: StaticString) {
        AutoFillTrace.log("vc.\(name: step) instance=\(instance: self) inWindow=\(viewIfLoaded?.window != nil) context=\(instance: extensionContext)")
    }
    override func viewWillAppear(_ animated: Bool) { super.viewWillAppear(animated); traceView("viewWillAppear") }
    override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); traceView("viewWillDisappear") }
    override func viewDidDisappear(_ animated: Bool) { super.viewDidDisappear(animated); traceView("viewDidDisappear") }
    #endif

    override func viewDidLoad() {
        super.viewDidLoad()
        #if DEBUG
        traceView("viewDidLoad")
        #endif
        navigationItem.title = "LocalGateKeys"
        overrideUserInterfaceStyle = Self.interfaceStyle(AppSettings.shared.appearance)
        table.dataSource = self; table.delegate = self
        table.translatesAutoresizingMaskIntoConstraints = false
        message.numberOfLines = 0; message.textAlignment = .center; message.textColor = Palette.uiColor(.secondaryText)
        message.translatesAutoresizingMaskIntoConstraints = false
        let cancel = UIButton(type: .system)
        cancel.setTitle("Cancel", for: .normal)
        cancel.addAction(UIAction { [weak self] _ in
            AutoFillTrace.log("vc.cancelButton tapped")
            self?.cancel(.userCanceled)
        }, for: .touchUpInside)
        cancel.translatesAutoresizingMaskIntoConstraints = false
        view.backgroundColor = Palette.uiColor(.background)
        // The app's aurora behind the list; the rows stay on the solid group surface.
        let aurora = UIHostingController(rootView: AuroraBackground())
        aurora.view.backgroundColor = .clear
        aurora.view.translatesAutoresizingMaskIntoConstraints = false
        addChild(aurora); view.addSubview(aurora.view); aurora.didMove(toParent: self)
        NSLayoutConstraint.activate([
            aurora.view.topAnchor.constraint(equalTo: view.topAnchor),
            aurora.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            aurora.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            aurora.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        table.backgroundColor = .clear
        table.separatorColor = Palette.uiColor(.separator)
        view.tintColor = Palette.uiColor(.accentText)
        [table, message, cancel].forEach(view.addSubview)
        NSLayoutConstraint.activate([
            cancel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            cancel.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -16),
            table.topAnchor.constraint(equalTo: cancel.bottomAnchor, constant: 4),
            table.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            table.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            table.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            message.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            message.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            message.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
        ])
    }

    /// Face ID can start only now: before it, LocalAuthentication fails at once with -1004 (notInteractive).
    /// Starts the request `prepareInterface…`/`prepareCredentialList` queued (`AppearanceGate`).
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        #if DEBUG
        traceView("viewDidAppear")
        #endif
        driver.viewDidAppear()
    }

    /// The Appearance setting the app wrote to the app group.
    static func interfaceStyle(_ a: Appearance) -> UIUserInterfaceStyle {
        switch a {
        case .system: .unspecified
        case .light: .light
        case .dark: .dark
        }
    }

    // MARK: AutoFill entry points (lifecycle in CredentialRequestDriver)
    //
    // `nonisolated`: AutoFill may deliver these on a background queue (the no-UI
    // `provideCredentialWithoutUserInteraction` especially). A main-actor override would trap there in its
    // @objc thunk before running, so a QuickType pick filled nothing. Each one reads the request into
    // Sendable values on the delivering thread, then runs on the main actor through `MainThreadEntry`.

    override nonisolated func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let urls = AutoFillMatcher.candidateURLs(serviceIdentifiers)
        AutoFillTrace.log("entry prepareCredentialList(for:) services=\(hosts: urls) instance=\(instance: self)")
        MainThreadEntry.run { [weak self] in
            guard let driver = self?.driver else { return }
            driver.whenAppeared("list") { driver.beginList(urls: urls) }
        }
    }

    /// A passkey-capable page (iOS 17): the usable passkeys for its relying party. With "Offer passkeys" off,
    /// the password list as before.
    override nonisolated func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                                    requestParameters: ASPasskeyCredentialRequestParameters) {
        let urls = AutoFillMatcher.candidateURLs(serviceIdentifiers)
        let rpID = requestParameters.relyingPartyIdentifier, allowed = requestParameters.allowedCredentials
        AutoFillTrace.log("entry prepareCredentialList(for:requestParameters:) services=\(hosts: urls) rp=\(host: rpID) allowed=\(allowed.count) instance=\(instance: self)")
        let clientDataHash = requestParameters.clientDataHash
        MainThreadEntry.run { [weak self] in
            guard let driver = self?.driver else { return }
            guard AppSettings.shared.offerPasskeys else { return driver.whenAppeared("list") { driver.beginList(urls: urls) } }
            driver.whenAppeared("passkeyList") {
                driver.beginPasskeyList(rpID: rpID, allowed: allowed, clientDataHash: clientDataHash)
            }
        }
    }

    /// Filling or signing from QuickType without UI would skip Face ID: always ask for the interface,
    /// for passwords and passkeys (`ASPasskeyCredentialRequest`) alike.
    override nonisolated func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        AutoFillTrace.log("entry provideCredentialWithoutUserInteraction(for: ASCredentialRequest) \(Self.describe(credentialRequest)) instance=\(instance: self)")
        MainThreadEntry.run { [weak self] in
            AutoFillTrace.log("vc.cancelRequest code=\(ASExtensionError.userInteractionRequired.rawValue)(userInteractionRequired) self=\(self != nil) context=\(instance: self?.extensionContext)")
            self?.extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain,
                                                                    code: ASExtensionError.userInteractionRequired.rawValue))
        }
    }

    override nonisolated func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        AutoFillTrace.log("entry prepareInterfaceToProvideCredential(for: ASCredentialRequest) \(Self.describe(credentialRequest)) instance=\(instance: self)")
        let route = CredentialRequestRoute.of(credentialRequest)
        MainThreadEntry.run { [weak self] in
            AutoFillTrace.log("vc.prepareInterface on main self=\(self != nil) viewLoaded=\(self?.isViewLoaded == true) inWindow=\(self?.viewIfLoaded?.window != nil) context=\(instance: self?.extensionContext)")
            guard let driver = self?.driver else { return }
            // No record id: answered at once, nothing to authenticate.
            guard route != .identityNotFound else { return driver.begin(route) }
            driver.whenAppeared("identity") { driver.begin(route) }
        }
    }

    /// The request's class, type, record id (last 6) and service host: never the user name.
    nonisolated static func describe(_ r: any ASCredentialRequest) -> TraceMessage {
        let identity = r.credentialIdentity
        let service: String? = (identity as? ASPasswordCredentialIdentity)?.serviceIdentifier.identifier
            ?? (identity as? ASPasskeyCredentialIdentity)?.relyingPartyIdentifier
        let serviceType = (identity as? ASPasswordCredentialIdentity)?.serviceIdentifier.type.rawValue ?? -1
        return "request=\(type: type(of: r)) requestType=\(r.type.rawValue) identity=\(type: type(of: identity)) recordID=\(rid: identity.recordIdentifier) service=\(host: service) serviceType=\(serviceType)"
    }

    #if DEBUG
    // Older entry points, traced only to see whether iOS still calls them; each then does what the system's
    // default would (super), on the main actor.
    @available(iOS, deprecated: 17.0)
    override nonisolated func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        AutoFillTrace.log("entry DEPRECATED provideCredentialWithoutUserInteraction(for: ASPasswordCredentialIdentity) recordID=\(rid: credentialIdentity.recordIdentifier) service=\(host: credentialIdentity.serviceIdentifier.identifier)")
        let identity = credentialIdentity
        MainThreadEntry.run { [weak self] in self?.superProvideWithoutUI(identity) }
    }
    @available(iOS, deprecated: 17.0)
    override nonisolated func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        AutoFillTrace.log("entry DEPRECATED prepareInterfaceToProvideCredential(for: ASPasswordCredentialIdentity) recordID=\(rid: credentialIdentity.recordIdentifier) service=\(host: credentialIdentity.serviceIdentifier.identifier)")
        let identity = credentialIdentity
        MainThreadEntry.run { [weak self] in self?.superPrepareInterface(identity) }
    }
    @available(iOS, deprecated: 17.0)
    private func superProvideWithoutUI(_ i: ASPasswordCredentialIdentity) { super.provideCredentialWithoutUserInteraction(for: i) }
    @available(iOS, deprecated: 17.0)
    private func superPrepareInterface(_ i: ASPasswordCredentialIdentity) { super.prepareInterfaceToProvideCredential(for: i) }

    override func beginRequest(with context: NSExtensionContext) {
        AutoFillTrace.log("vc.beginRequest instance=\(instance: self) context=\(instance: context)")
        super.beginRequest(with: context)
    }
    #endif

    /// Passkey creation (iOS 17): confirm site and account, then Face ID, then one commit. With "Offer
    /// passkeys" off, or for a request that is not a passkey request, iOS falls back (`.failed`).
    override nonisolated func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        AutoFillTrace.log("entry prepareInterface(forPasskeyRegistration:) \(Self.describe(registrationRequest))")
        // iOS 17 hands over no relying-party name or display name: the title falls back to the rp id.
        var request: PasskeyRegistrationRequest?
        if let pk = registrationRequest as? ASPasskeyCredentialRequest,
           let identity = pk.credentialIdentity as? ASPasskeyCredentialIdentity {
            request = PasskeyRegistrationRequest(rpID: identity.relyingPartyIdentifier, rpName: "",
                                                 userName: identity.userName, userDisplayName: "",
                                                 userHandle: identity.userHandle, clientDataHash: pk.clientDataHash,
                                                 algorithms: pk.supportedAlgorithms.map { $0.rawValue })
        }
        let parsed = request
        MainThreadEntry.run { [weak self] in
            guard let self else { return }
            guard AppSettings.shared.offerPasskeys, let parsed else { return self.driver.finishImmediately(.failed) }
            // The sheet's Create starts Face ID: show it only once the view is on screen.
            self.driver.whenAppeared("registration") { [weak self] in self?.showCreateSheet(parsed) }
        }
    }

    private func showCreateSheet(_ request: PasskeyRegistrationRequest) {
        let sheet = UIHostingController(rootView: PasskeyCreateSheet(
            rpID: PasskeyRecord.normaliseRPID(request.rpID), userName: request.userName,
            create: { [weak self] in self?.driver.beginRegistration(request) },
            cancel: { [weak self] in self?.cancel(.userCanceled) }))
        sheet.view.backgroundColor = .clear
        sheet.view.translatesAutoresizingMaskIntoConstraints = false
        addChild(sheet); view.addSubview(sheet.view); sheet.didMove(toParent: self)
        NSLayoutConstraint.activate([
            sheet.view.topAnchor.constraint(equalTo: view.topAnchor),
            sheet.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            sheet.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            sheet.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        createSheet = sheet
    }

    private func dismissCreateSheet() {
        guard let sheet = createSheet else { return }
        sheet.willMove(toParent: nil); sheet.view.removeFromSuperview(); sheet.removeFromParent()
        createSheet = nil
    }

    private func cancel(_ code: ASExtensionError.Code) { driver.cancel(code) }

    // MARK: CredentialRequestSink

    func showList(_ list: [AutoFillLogin]) {
        AutoFillTrace.log("vc.showList count=\(list.count)")
        passkeyRows = []
        logins = list
        message.text = list.isEmpty ? "No saved login matches this site." : nil
        table.reloadData()
    }

    func completeRequest(user: String, password: String) {
        AutoFillTrace.log("vc.completeRequest(withSelectedCredential:) context=\(instance: extensionContext) inWindow=\(viewIfLoaded?.window != nil)")
        logins = []; table.reloadData()
        extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password))
    }

    func showPasskeys(_ rows: [PasskeyCandidate]) {
        logins = []
        passkeyRows = rows
        message.text = rows.isEmpty ? "No saved passkey for this site." : nil
        table.reloadData()
    }

    func completePasskey(_ a: PasskeyAssertion) {
        AutoFillTrace.log("vc.completeAssertionRequest context=\(instance: extensionContext)")
        logins = []; passkeyRows = []; table.reloadData()
        let credential = ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: a.rpID, signature: a.signature,
                                                      clientDataHash: a.clientDataHash, authenticatorData: a.authenticatorData,
                                                      credentialID: a.credentialID)
        extensionContext.completeAssertionRequest(using: credential)
    }

    func completeRegistration(_ r: PasskeyRegistration) {
        AutoFillTrace.log("vc.completeRegistrationRequest context=\(instance: extensionContext)")
        dismissCreateSheet()
        let credential = ASPasskeyRegistrationCredential(relyingParty: r.rpID, clientDataHash: r.clientDataHash,
                                                         credentialID: r.credentialID, attestationObject: r.attestationObject)
        extensionContext.completeRegistrationRequest(using: credential)
    }

    func cancelRequest(_ code: ASExtensionError.Code) {
        AutoFillTrace.log("vc.cancelRequest code=\(code.rawValue) context=\(instance: extensionContext) inWindow=\(viewIfLoaded?.window != nil)")
        dismissCreateSheet()
        logins = []; passkeyRows = []; table.reloadData()
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }

    // MARK: list

    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int { logins.count + passkeyRows.count }

    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = UITableViewCell(style: .subtitle, reuseIdentifier: nil)
        var c = cell.defaultContentConfiguration()
        if logins.indices.contains(indexPath.row) {
            let l = logins[indexPath.row]
            c.text = l.title; c.secondaryText = l.username
        } else {
            let p = passkeyRows[indexPath.row - logins.count]
            c.text = p.title.isEmpty ? p.rpID : p.title; c.secondaryText = p.userName
            c.image = UIImage(systemName: "person.badge.key")
        }
        c.textProperties.color = Palette.uiColor(.text)
        c.secondaryTextProperties.color = Palette.uiColor(.secondaryText)
        cell.contentConfiguration = c
        // Content sits on the solid group surface, never on glass.
        cell.backgroundColor = Palette.uiColor(.groupSurface)
        return cell
    }

    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        AutoFillTrace.log("vc.didSelectRow row=\(indexPath.row)")
        if logins.indices.contains(indexPath.row) { return driver.select(logins[indexPath.row]) }
        let i = indexPath.row - logins.count
        guard passkeyRows.indices.contains(i) else { return }
        driver.selectPasskey(passkeyRows[i])
    }
}
