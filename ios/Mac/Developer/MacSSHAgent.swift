import Foundation
import Observation
import LGKCore
import AppSharedMac

/// Settings › Developer: this Mac's own choices (Global rules: per-device settings, never item fields, never synced).
enum DeveloperSettings {
    static let agentKey = "settings.mac.developer.sshAgent"
    static let keysKey = "settings.mac.developer.sshKeys"
    /// Windows `MAX_ID_LIST`.
    static let maxKeys = 1000

    /// The agent is off by default.
    static func agentOn(_ defaults: UserDefaults) -> Bool { defaults.bool(forKey: agentKey) }

    /// The SSH key items the agent offers, in the order they were switched on (each is off by default).
    static func offeredKeys(_ defaults: UserDefaults) -> [String] {
        (defaults.array(forKey: keysKey) ?? []).compactMap { $0 as? String }
    }

    static func setOffered(_ id: String, _ on: Bool, defaults: UserDefaults) {
        var ids = offeredKeys(defaults).filter { $0 != id }
        if on { ids = Array(ids.suffix(maxKeys - 1)) + [id] }
        defaults.set(ids, forKey: keysKey)
    }
}

/// An SSH key item the agent may offer: its public half, never the private key.
struct OfferedSSHKey: Equatable, Sendable {
    let id: String
    let title: String
    let blob: [UInt8]
    let comment: String
}

/// What a signature needs from the item once approved.
struct SSHKeySecret: Sendable {
    let privateKey: String
    let passphrase: String
}

/// The app-wide SSH agent (Windows `SshAgentService` plus the server's lifecycle): the socket runs while the setting
/// is on, also while locked (it then lists nothing and signs nothing). Signatures are approved through the unlocked
/// window's `StrictItemGate`; with no window (locked) they are refused.
@MainActor @Observable
final class MacSSHAgent {
    static let shared = MacSSHAgent(defaults: .standard, store: {
        // No SSH key is served from the duress password's second vault (sub-plan 08).
        guard let lock = MacAppEnvironment.lockState, lock.state == .unlocked, !lock.isSecondSession else { return nil }
        return lock.store
    })

    private(set) var status: AgentSocketServer.Status = .stopped
    /// Where the socket is (or would be); nil without the app-group container.
    let socketPath: String?
    /// The unlocked window's gate (set while the window is shown).
    @ObservationIgnored weak var gate: StrictItemGate?
    /// Shows the window before a master password sheet.
    @ObservationIgnored var bringForward: @MainActor () -> Void = { QuickAccessBridge.activate() }
    @ObservationIgnored let defaults: UserDefaults
    @ObservationIgnored private let store: () -> (any ItemStore)?
    @ObservationIgnored private var server: AgentSocketServer?

    init(defaults: UserDefaults, store: @escaping () -> (any ItemStore)?, socketPath: String? = AgentSocketPath.defaultURL()?.path) {
        self.defaults = defaults; self.store = store; self.socketPath = socketPath
    }

    var enabled: Bool { DeveloperSettings.agentOn(defaults) }

    /// Starts or stops the socket to match the setting (at launch and when it changes).
    func applySetting() {
        guard enabled else {
            server?.stop()
            server = nil
            status = .stopped
            return
        }
        guard let socketPath else { status = .unavailable; return }
        if let server, server.status == .running { status = .running; return }
        let server = self.server ?? AgentSocketServer(backend: MacSSHAgentBackend(agent: self))
        self.server = server
        status = server.start(path: socketPath)
    }

    func setEnabled(_ on: Bool) {
        defaults.set(on, forKey: DeveloperSettings.agentKey)
        applySetting()
    }

    func attach(_ gate: StrictItemGate) { self.gate = gate }

    func detach(_ gate: StrictItemGate) { if self.gate === gate { self.gate = nil } }

    // MARK: keys

    /// The open store while unlocked.
    func unlockedStore() -> (any ItemStore)? { store() }

    /// The vault's SSH key items, by id (none while locked).
    func sshItems() -> [String: VaultItem] {
        guard let store = self.store(), let snapshot = try? store.load() else { return [:] }
        var items: [String: VaultItem] = [:]
        for item in VaultItem.items(from: snapshot) where item.kind == "ssh_key" { items[item.id] = item }
        return items
    }

    /// Windows `_offered`: every switched-on SSH key item with a usable public half (an encrypted key saved without its
    /// passphrase, sk-* or PuTTY keys have none; encrypted PEM keys can't be read on the Mac), in allow-list order. The
    /// comment is the public key's own.
    func offeredKeys() -> [OfferedSSHKey] {
        guard enabled else { return [] }
        let items = sshItems()
        return DeveloperSettings.offeredKeys(defaults).compactMap { id in
            guard let item = items[id], let payload = item.record["payload"]?.objectValue,
                  let line = payload["public_key"]?.stringValue, let parsed = SSHKey.publicLineBlob(line),
                  !SSHKey.isEncryptedPEM(payload["private_key"]?.stringValue ?? "") else { return nil }
            return OfferedSSHKey(id: id, title: item.title, blob: parsed.blob, comment: parsed.comment)
        }
    }

    /// The approval, then the key's secret. Re-checks after the prompt that the vault is still unlocked and the key
    /// still offered (Windows `_secret`); nil when anything refused.
    func approveAndFetch(blob: [UInt8], peer: SSHAgentPeer, host: String?) async -> SSHKeySecret? {
        guard let match = offeredKeys().first(where: { $0.blob == blob }), let gate else { return nil }
        let approved = await gate.approveSSH(program: peer.path, programName: peer.displayName, itemID: match.id,
                                             title: match.title, host: host, bringForward: bringForward)
        guard approved, !Task.isCancelled else { return nil }
        guard offeredKeys().contains(where: { $0.id == match.id && $0.blob == blob }),
              let payload = sshItems()[match.id]?.record["payload"]?.objectValue else { return nil }
        return SSHKeySecret(privateKey: payload["private_key"]?.stringValue ?? "",
                            passphrase: payload["passphrase"]?.stringValue ?? "")
    }
}

/// The socket's backend (Windows `SshAgentService`): runs on connection threads and asks the main actor.
struct MacSSHAgentBackend: SSHAgentBackend {
    /// Windows `SIGN_DEADLINE`: the whole request, prompt included, so a client never hangs on a prompt nobody answers.
    static let signDeadline: TimeInterval = 95
    /// Windows `VAULT_LOCK_TIMEOUT`: listing never waits long.
    static let listTimeout: TimeInterval = 5

    let agent: MacSSHAgent
    var signDeadline = MacSSHAgentBackend.signDeadline
    var now: @Sendable () -> Date = { Date() }
    var knownHosts: @Sendable () -> String? = { KnownHosts.read() }

    func identities() -> [SSHAgentIdentity] {
        MainActorBridge.run(timeout: Self.listTimeout) { [agent] () async -> [SSHAgentIdentity]? in
            agent.offeredKeys().map { SSHAgentIdentity(blob: $0.blob, comment: $0.comment) }
        } ?? []
    }

    func sign(blob: [UInt8], data: [UInt8], flags: UInt32, peer: SSHAgentPeer, boundHost: String?) -> [UInt8]? {
        let deadline = now().addingTimeInterval(signDeadline)
        let keyType = SSHWire.blobType(blob)
        guard SSHKey.supportedTypes.contains(keyType) else { return nil }
        if keyType == "ssh-rsa" && flags & (SSHKey.rsaSHA256 | SSHKey.rsaSHA512) == 0 { return nil }   // SHA-1: refused
        let secret = MainActorBridge.run(timeout: deadline.timeIntervalSince(now())) { [agent] () async -> SSHKeySecret? in
            await agent.approveAndFetch(blob: blob, peer: peer, host: boundHost)
        }
        guard let secret,
              let key = try? SSHKey.load(secret.privateKey, passphrase: secret.passphrase.isEmpty ? nil : secret.passphrase),
              key.publicBlob == blob, now() < deadline else { return nil }
        return try? key.sign(data, flags: flags)
    }

    func verifyBind(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8]) -> Bool {
        SSHSignature.verify(publicBlob: hostKey, signature: signature, data: sessionID)
    }

    func hostName(for hostKey: [UInt8]) -> String { KnownHosts.name(for: hostKey, knownHosts: knownHosts()) }
}

/// Runs main-actor work from a connection thread and waits for it, up to a timeout (the work is cancelled then).
enum MainActorBridge {
    static func run<T: Sendable>(timeout: TimeInterval, _ body: @escaping @MainActor @Sendable () async -> T?) -> T? {
        dispatchPrecondition(condition: .notOnQueue(.main))
        guard timeout > 0 else { return nil }
        let result = ResultBox<T>()
        let done = DispatchSemaphore(value: 0)
        let task = Task { @MainActor in
            result.set(await body())
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else {
            task.cancel()
            return nil
        }
        return result.value
    }
}

private final class ResultBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T?

    var value: T? {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func set(_ value: T?) {
        lock.lock()
        stored = value
        lock.unlock()
    }
}
