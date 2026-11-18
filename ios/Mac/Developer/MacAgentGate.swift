import Foundation
import Observation
import LGKCore
import AppSharedMac

// AI agents on the Mac (Pro): `lgk mcp` (Windows `cli/mcp_server.py`) forwards each tool call to `mcp.sock`; the app
// answers through LGKCore's `AgentGate` (Windows `agent_gate.py`), which asks the user in the approval panel and writes
// the access log. The Safari extension asks `fill.sock` for an approved sign-in after the user's own click on the
// LocalGateKeys icon in a sign-in field. Both sockets run only while Settings › Developer › "Allow AI agents to use
// LocalGateKeys" is on (off by default).

extension DeveloperSettings {
    static let aiAgentsKey = "settings.mac.developer.aiAgents"
    /// "Require Touch ID for each approval" (Windows `require_hello_for_agents`); off by default.
    static let aiAgentsTouchIDKey = "settings.mac.developer.aiAgentsTouchID"

    static func agentSettings(_ defaults: UserDefaults) -> AgentGate.Settings {
        AgentGate.Settings(agentsEnabled: defaults.bool(forKey: aiAgentsKey), requireHello: defaults.bool(forKey: aiAgentsTouchIDKey))
    }
}

enum AgentSocketNames {
    static let mcp = "mcp.sock"
    static let fill = "fill.sock"

    /// `<app-group container>/mcp.sock`: the group `lgk` holds too.
    static func mcpURL() -> URL? { AppGroup.containerURL?.appendingPathComponent(mcp, isDirectory: false) }
    /// `<Safari app-group container>/fill.sock`: the only group the Safari extension holds.
    static func fillURL() -> URL? { AppGroup.safariContainerURL?.appendingPathComponent(fill, isDirectory: false) }

    /// `lgk` in the app bundle (`Contents/MacOS/lgk`).
    static var lgkURL: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/lgk", isDirectory: false) }

    /// The command that adds LocalGateKeys to Claude Code (other MCP clients take the same program and argument).
    static var addCommand: String { "claude mcp add localgatekeys -- \"\(lgkURL.path)\" mcp" }
}

/// What the gate reads from the open vault: logins without their secrets, and passkey names.
struct MacAgentVault: AgentVault {
    let loginRows: [AgentLoginRecord]
    let passkeyRows: [AgentPasskey]

    /// The record keys the gate and the fill offer read; the password and everything else stay out.
    static let keptKeys: Set<String> = ["kind", "scope", "policy", "username", "favorite"]

    init(items: [VaultItem]) {
        // Feature pack §4.3: a login with any access rule on is never offered to agents.
        loginRows = items.filter { $0.kind == "web" && !MacAccess.rules($0.record).anyRule }.map { item in
            AgentLoginRecord(id: item.id, title: item.title, kind: item.kind,
                             record: item.record.filter { Self.keptKeys.contains($0.key) })
        }
        passkeyRows = items.compactMap { AgentPasskey(record: $0.record) }
    }

    func logins() -> [AgentLoginRecord] { loginRows }
    func passkeys() -> [AgentPasskey] { passkeyRows }
}

/// A weak reference the gate's closures can carry across threads; read on the main actor only.
private final class AgentOwner: @unchecked Sendable {
    weak var gate: MacAgentGate?
}

@MainActor @Observable
final class MacAgentGate {
    static let shared = MacAgentGate(defaults: .standard)
    /// An approval nobody answers is a no after this long (the agent's request then fails).
    nonisolated static let approvalTimeout: TimeInterval = 120

    struct Approval: Identifiable, Equatable {
        let id = UUID()
        let request: AgentApprovalRequest
    }

    private(set) var status: AgentSocketServer.Status = .stopped
    private(set) var fillStatus: AgentSocketServer.Status = .stopped
    /// The approval on screen.
    private(set) var pending: Approval?
    /// Touch ID could not be used: the panel asks for the master password.
    private(set) var needsPassword = false
    private(set) var message: String?
    private(set) var busy = false

    /// UserDefaults is documented as thread-safe.
    @ObservationIgnored nonisolated(unsafe) let defaults: UserDefaults
    @ObservationIgnored nonisolated let core: AgentGate
    @ObservationIgnored nonisolated let releases = AgentReleaseBook()
    @ObservationIgnored nonisolated let matcher: URLMatcher
    @ObservationIgnored private let owner: AgentOwner
    @ObservationIgnored private var mcpServer: AgentLineServer?
    @ObservationIgnored private var fillServer: AgentLineServer?
    @ObservationIgnored private var continuation: CheckedContinuation<Bool, Never>?
    @ObservationIgnored private lazy var panel = AgentApprovalPanel()
    /// Shows the app (the unlock screen when locked).
    @ObservationIgnored var bringForward: @MainActor () -> Void = { QuickAccessBridge.activate() }

    init(defaults: UserDefaults, matcher: URLMatcher = SafariSaveService.bundledMatcher()) {
        let owner = AgentOwner()
        self.owner = owner
        self.defaults = defaults
        self.matcher = matcher
        nonisolated(unsafe) let defaults = defaults
        core = AgentGate(
            session: { MainActorBridge.run(timeout: 5) { owner.gate?.vault() } },
            settings: { DeveloperSettings.agentSettings(defaults) },
            confirm: { request in
                MainActorBridge.run(timeout: MacAgentGate.approvalTimeout + 10) { await owner.gate?.ask(request) } ?? false
            },
            activity: { event, result in _ = MainActorBridge.run(timeout: 5) { owner.gate?.record(event, result) } },
            isPro: { MainActorBridge.run(timeout: 5) { MacAppEnvironment.pro.isPro } ?? false },
            requestUnlock: { Task { @MainActor in owner.gate?.bringForward() } },
            matcher: matcher,
            passkeyOutcomes: false)
        owner.gate = self
    }

    var enabled: Bool { defaults.bool(forKey: DeveloperSettings.aiAgentsKey) }
    var requireTouchID: Bool { defaults.bool(forKey: DeveloperSettings.aiAgentsTouchIDKey) }

    /// Starts or stops both sockets to match the setting (at launch and when it changes).
    func applySetting() {
        guard enabled else {
            mcpServer?.stop(); mcpServer = nil
            fillServer?.stop(); fillServer = nil
            status = .stopped; fillStatus = .stopped
            if pending != nil { finish(false) }
            return
        }
        if let path = AgentSocketNames.mcpURL()?.path {
            if mcpServer?.status != .running {
                let gate = core
                let server = mcpServer ?? AgentLineServer(label: "app.localgatekeys.agent-mcp") { request, peer in
                    AgentDispatch.reply(gate, request: request, pid: peer.pid, process: peer.programName)
                }
                mcpServer = server
                status = server.start(path: path)
            } else {
                status = .running
            }
        } else {
            status = .unavailable
        }
        if let path = AgentSocketNames.fillURL()?.path {
            if fillServer?.status != .running {
                let server = fillServer ?? AgentLineServer(label: "app.localgatekeys.agent-fill",
                                                           admit: { AgentPeerCheck.isSafariExtension($0) }) { [owner] request, _ in
                    MacAgentFill.reply(request, owner: owner)
                }
                fillServer = server
                fillStatus = server.start(path: path)
            } else {
                fillStatus = .running
            }
        } else {
            fillStatus = .unavailable
        }
    }

    func setEnabled(_ on: Bool) {
        defaults.set(on, forKey: DeveloperSettings.aiAgentsKey)
        applySetting()
    }

    func setRequireTouchID(_ on: Bool) { defaults.set(on, forKey: DeveloperSettings.aiAgentsTouchIDKey) }

    // MARK: vault and log

    /// The open vault without its secrets; nil while locked.
    func vault() -> MacAgentVault? {
        guard let lock = MacAppEnvironment.lockState, lock.state == .unlocked, !lock.isSecondSession, let store = lock.store,
              let snapshot = try? store.load() else { return nil }
        return MacAgentVault(items: VaultItem.items(from: snapshot))
    }

    /// The login's user name and password for a pick on the page, re-checked now: unlocked, still a web login the
    /// owner allows for AI agents, not strict and not fill-never. Nil otherwise.
    func credential(_ entryID: String) -> (username: String, password: String)? {
        guard let lock = MacAppEnvironment.lockState, lock.state == .unlocked, !lock.isSecondSession, let store = lock.store,
              let snapshot = try? store.load(),
              let item = VaultItem.items(from: snapshot).first(where: { $0.id == entryID && $0.kind == "web" }),
              AgentText.agentsMayUse(item.record), AgentPolicy.usable(item.record), !MacAccess.rules(item.record).anyRule,
              let password = item.record["password"]?.stringValue else { return nil }
        return (item.username, password)
    }

    /// Writes one `agent.*` access-log event (event and result words only).
    @discardableResult
    func record(_ event: String, _ result: String) -> Bool {
        guard let event = ActivityRecorder.Event(rawValue: event), let lock = MacAppEnvironment.lockState else { return false }
        lock.activity.record(event, result: ActivityRecorder.Result(rawValue: result) ?? .failed)
        return true
    }

    // MARK: approval

    /// Shows the approval panel and waits for the answer: "Approve once" is the only yes; Deny, closing, a lock or
    /// 120 s without an answer are a no.
    func ask(_ request: AgentApprovalRequest) async -> Bool {
        guard pending == nil, let lock = MacAppEnvironment.lockState, lock.isUnlocked, !lock.isSecondSession else { return false }
        let generation = lock.sessionGeneration
        let approval = Approval(request: request)
        let timeout = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Self.approvalTimeout))
            if self?.pending?.id == approval.id { self?.finish(false) }
        }
        let approved = await withCheckedContinuation { continuation in
            self.continuation = continuation
            pending = approval
            needsPassword = false
            message = nil
            panel.show(self)
        }
        timeout.cancel()
        return approved && lock.isUnlocked && lock.sessionGeneration == generation
    }

    /// "Approve once": with "Require Touch ID" on, Touch ID first (the master password when Touch ID cannot be used).
    func approve(password: String = "") async {
        guard let approval = pending, !busy else { return }
        if approval.request.hello {
            guard let lock = MacAppEnvironment.lockState else { finish(false); return }
            busy = true
            defer { busy = false }
            if needsPassword {
                guard !password.isEmpty else { return }
                do {
                    try await lock.verifyPassword(password)
                } catch {
                    message = MacLockModel.describe(error, now: Date()) ?? String(localized: "The password could not be checked.")
                    return
                }
            } else if lock.routineTouchIDEnabled {
                do {
                    try await lock.verifyWithTouchID(reason: String(localized: "agents.approve.touchID",
                                                                    defaultValue: "approve an AI agent's request"))
                } catch is CancellationError {
                    if pending?.id == approval.id { finish(false) }
                    return
                } catch {
                    needsPassword = true
                    message = String(localized: "Touch ID didn't work. Use your master password.")
                    return
                }
            } else {
                needsPassword = true
                return
            }
            guard pending?.id == approval.id else { return }
        }
        finish(true)
    }

    func deny() { finish(false) }

    private func finish(_ approved: Bool) {
        let waiting = continuation
        continuation = nil
        pending = nil
        needsPassword = false
        message = nil
        panel.hide()
        waiting?.resume(returning: approved)
    }

    /// Locking drops the approval on screen (a no).
    func lockReset() { if pending != nil { finish(false) } }
}

/// The Safari extension's side (`fill.sock`, Windows `browser_broker._fill_grant_browser` and the picker's release).
/// Runs on a connection thread.
enum MacAgentFill {
    static func notFound() -> [String: JSONValue] { ["ok": .bool(false), "error": .string("not_found")] }

    fileprivate static func reply(_ request: [String: JSONValue], owner: AgentOwner) -> [String: JSONValue] {
        guard let gate = MainActorBridge.run(timeout: 5, { owner.gate }) else { return notFound() }
        guard case .string(let action)? = request["action"] else { return notFound() }
        var url = ""
        if case .string(let given)? = request["url"] { url = given }
        let origin = (try? Origin.originOf(url)) ?? ""
        switch action {
        case "agent_status":
            // Whether the icon should offer an agent's sign-in at all (Safari fills nothing else).
            let settings = DeveloperSettings.agentSettings(gate.defaults)
            let pro = settings.agentsEnabled && (MainActorBridge.run(timeout: 5) { MacAppEnvironment.pro.isPro } ?? false)
            return ["ok": .bool(true), "agent": .bool(pro)]
        case "agent_offer":
            return offer(gate, url: url, origin: origin)
        case "agent_release":
            var token: String?, entryID: String?
            if case .string(let value)? = request["grant"] { token = value }
            if case .string(let value)? = request["entry_id"] { entryID = value }
            guard !origin.isEmpty, let entry = gate.releases.take(token: token, entryID: entryID, origin: origin),
                  let credential = MainActorBridge.run(timeout: 5, { () -> AgentCredential? in
                      gate.credential(entry).map { AgentCredential(username: $0.username, password: $0.password) }
                  }) else { return notFound() }
            return ["ok": .bool(true), "username": .string(credential.username), "password": .string(credential.password)]
        default:
            return notFound()
        }
    }

    /// Only an armed, unexpired, unused grant whose approved hosts include this page's exact host takes effect; it is
    /// used up here. The page gets the approved logins as picker choices and a one-use offer token.
    static func offer(_ gate: MacAgentGate, url: String, origin: String) -> [String: JSONValue] {
        guard !origin.isEmpty else { return notFound() }
        guard let grant = gate.core.takeForOrigin(origin) else {
            if gate.core.passkeyPending(origin) {
                return ["ok": .bool(false), "error": .string("agent_passkey"),
                        "message": .string(String(localized: "agents.page.usePasskey",
                                                  defaultValue: "This sign-in uses a passkey. Choose the site's passkey sign-in."))]
            }
            return notFound()
        }
        guard let vault = MainActorBridge.run(timeout: 5, { gate.vault() }) else {
            gate.core.finish(grant, outcome: "none")
            return notFound()
        }
        let choices = AgentFillOffer.choices(grant: grant, pageURL: url, vault: vault, matcher: gate.matcher)
        guard !choices.isEmpty, let token = gate.releases.issue(origin: origin, entryIDs: choices.map(\.entryID)) else {
            gate.core.finish(grant, outcome: "none")
            return notFound()
        }
        gate.core.finish(grant, outcome: "picker")   // the user picks the login with a click in the picker
        return ["ok": .bool(true), "agent": .bool(true), "grant": .string(token), "origin": .string(origin),
                "choices": .array(choices.map { choice in
                    .object(["entry_id": .string(choice.entryID), "username": .string(choice.username),
                             "label": .string(choice.label), "favorite": .bool(choice.favorite),
                             "require_master_password": .bool(false), "match": .string(choice.match.rawValue)])
                })]
    }
}

private struct AgentCredential: Sendable {
    let username: String
    let password: String
}
