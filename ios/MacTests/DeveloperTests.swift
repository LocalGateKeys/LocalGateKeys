import XCTest
import Darwin
import LGKCore
@testable import AppSharedMac

/// Applies changes like LocalStore (a stale base is refused).
private final class DevMemoryStore: ItemStore, @unchecked Sendable {
    var snapshot = StoreSnapshot()
    func load() throws -> StoreSnapshot { snapshot }
    func commit(_ change: StoreChange) throws {
        guard change.baseRevision == snapshot.revision else {
            throw LocalStoreError.stale(expected: change.baseRevision, actual: snapshot.revision)
        }
        snapshot = StoreSnapshot(records: change.records, meta: change.meta, sync: change.sync, revision: snapshot.revision + 1)
    }
}

@MainActor
private final class DevFakeVault: MasterPasswordService {
    let right = "correct horse"
    var hasVault = true
    var isUnlocked = true
    var touchIDAvailable = false
    var generation = 1
    var sessionGeneration: Int { generation }
    func verifyPassword(_ password: String) async throws {
        guard password == right else { throw MacVaultError.wrongPassword(retryAfter: nil) }
    }
    func changePassword(old: String, new: String) async throws {}
    func setTouchID(_ on: Bool, password: String) async throws {}
}

/// Records what the socket asked for.
private final class RecordingBackend: SSHAgentBackend, @unchecked Sendable {
    var verifyResult = true
    var signResult: [UInt8]? = [9, 9]
    private(set) var signCalls = 0
    private(set) var verifyCalls = 0
    private(set) var lastHost: String?
    func identities() -> [SSHAgentIdentity] { [SSHAgentIdentity(blob: [7], comment: "laptop")] }
    func sign(blob: [UInt8], data: [UInt8], flags: UInt32, peer: SSHAgentPeer, boundHost: String?) -> [UInt8]? {
        signCalls += 1
        lastHost = boundHost
        return signResult
    }
    func verifyBind(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8]) -> Bool { verifyCalls += 1; return verifyResult }
    func hostName(for hostKey: [UInt8]) -> String { "example.org" }
}

/// Plain paths instead of security-scoped bookmarks.
private struct PathBookmarks: BookmarkResolving {
    func bookmark(for url: URL) throws -> [UInt8] { Array(url.path.utf8) }
    func resolve(_ bytes: [UInt8]) throws -> (url: URL, refreshed: [UInt8]?) {
        (URL(fileURLWithPath: String(decoding: bytes, as: UTF8.self)), nil)
    }
}

private struct FixedClock: UnixClock { var now: Int64 = 1_700_000_000 }

/// Settings › Developer on the Mac: the SSH agent's replies (Windows `ssh_agent/server.py` rules), its socket, the
/// key allow-list and approvals, and the plain-secrets scan (Windows `secret_scan.py` rules).
@MainActor
final class DeveloperTests: XCTestCase {
    private static let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../..").standardized
    nonisolated(unsafe) private var dir: URL!
    nonisolated(unsafe) private var defaults: UserDefaults!
    nonisolated(unsafe) private var suite: String!

    override func setUpWithError() throws {
        // A short folder name: the socket test's path must fit in sun_path (104 bytes).
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(String(UUID().uuidString.prefix(8)))
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        suite = "lgk-dev-tests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
        defaults.removePersistentDomain(forName: suite)
    }

    private func vector(_ name: String) throws -> String {
        try String(contentsOf: Self.repo.appendingPathComponent("tests/vectors/ssh/\(name)"), encoding: .utf8)
    }

    // MARK: replies

    private func bind(forwarding: Bool) -> SSHAgentMessage {
        SSHAgentMessage(type: SSHAgentProtocol.extensionRequest, extensionName: SSHAgentProtocol.sessionBind,
                        bind: SSHSessionBind(hostKey: [1], sessionID: [2], signature: [3], forwarding: forwarding))
    }

    private let signRequest = SSHAgentMessage(type: SSHAgentProtocol.signRequest, keyBlob: [7], data: [1], flags: 0)

    func testForwardingBindMarksTheConnectionBeforeItsSignatureIsChecked() {
        let backend = RecordingBackend()
        backend.verifyResult = false
        var state = SSHAgentConnectionState()
        XCTAssertEqual(SSHAgentReplies.reply(to: bind(forwarding: true), state: &state, backend: backend).type, SSHAgentProtocol.failure)
        XCTAssertTrue(state.forwarding)
        XCTAssertFalse(state.bound)
        let list = SSHAgentReplies.reply(to: SSHAgentMessage(type: SSHAgentProtocol.requestIdentities), state: &state, backend: backend)
        XCTAssertEqual(list.type, SSHAgentProtocol.identitiesAnswer)
        XCTAssertEqual(list.identities, [])
        XCTAssertEqual(SSHAgentReplies.reply(to: signRequest, state: &state, backend: backend).type, SSHAgentProtocol.failure)
        XCTAssertEqual(backend.signCalls, 0, "a forwarded connection never signs")
        // Once forwarded, always forwarded: a later plain bind does not clear it.
        backend.verifyResult = true
        _ = SSHAgentReplies.reply(to: bind(forwarding: false), state: &state, backend: backend)
        XCTAssertTrue(state.forwarding)
    }

    func testOneBindPerConnectionNamesTheHost() {
        let backend = RecordingBackend()
        var state = SSHAgentConnectionState()
        XCTAssertEqual(SSHAgentReplies.reply(to: bind(forwarding: false), state: &state, backend: backend).type, SSHAgentProtocol.success)
        XCTAssertEqual(state.boundHost, "example.org")
        XCTAssertEqual(SSHAgentReplies.reply(to: bind(forwarding: false), state: &state, backend: backend).type, SSHAgentProtocol.failure)
        XCTAssertEqual(backend.verifyCalls, 1, "a second bind is refused before it is checked")
        let signed = SSHAgentReplies.reply(to: signRequest, state: &state, backend: backend)
        XCTAssertEqual(signed, SSHAgentMessage(type: SSHAgentProtocol.signResponse, signature: [9, 9]))
        XCTAssertEqual(backend.lastHost, "example.org")
    }

    func testEverythingElseFails() {
        let backend = RecordingBackend()
        var state = SSHAgentConnectionState()
        let types: [UInt8] = [17, 18, 19, 22, 25]   // add, remove, remove all, lock, add constrained
        for type in types {
            XCTAssertEqual(SSHAgentReplies.reply(to: SSHAgentMessage(type: type), state: &state, backend: backend).type, SSHAgentProtocol.failure)
        }
        let query = SSHAgentMessage(type: SSHAgentProtocol.extensionRequest, extensionName: "query")
        XCTAssertEqual(SSHAgentReplies.reply(to: query, state: &state, backend: backend).type, SSHAgentProtocol.failure)
        backend.signResult = nil
        XCTAssertEqual(SSHAgentReplies.reply(to: signRequest, state: &state, backend: backend).type, SSHAgentProtocol.failure)
        XCTAssertEqual(SSHAgentReplies.reply(to: SSHAgentMessage(type: SSHAgentProtocol.requestIdentities), state: &state,
                                             backend: backend).identities, [SSHAgentIdentity(blob: [7], comment: "laptop")])
    }

    func testKnownHostsNaming() {
        let key: [UInt8] = [0, 0, 0, 11] + Array("ssh-ed25519".utf8) + [0, 0, 0, 1, 42]
        let encoded = Data(key).base64EncodedString()
        let text = """
        # comment \(encoded)
        |1|hashed= ssh-ed25519 \(encoded)
        @cert-authority *.example ssh-ed25519 \(encoded)
        *.wild,!neg ssh-ed25519 \(encoded)
        other.example ssh-ed25519 AAAA
        [git.example]:2222,git.example ssh-ed25519 \(encoded)
        """
        XCTAssertEqual(KnownHosts.name(for: key, knownHosts: text), "git.example:2222")
        XCTAssertEqual(KnownHosts.name(for: key, knownHosts: "[host.example]:22 ssh-ed25519 \(encoded)\n"), "host.example")
        XCTAssertEqual(KnownHosts.name(for: key, knownHosts: "plain.example ssh-ed25519 \(encoded) a comment\n"), "plain.example")
        XCTAssertEqual(KnownHosts.name(for: key, knownHosts: nil), SSHKey.fingerprint(of: key))
        XCTAssertEqual(KnownHosts.name(for: key, knownHosts: "|1|x= ssh-ed25519 \(encoded)\n"), SSHKey.fingerprint(of: key))
    }

    func testSocketPathLimit() {
        XCTAssertTrue(AgentSocketPath.fits("/Users/a/Library/Group Containers/ABCDE12345.group.app.localgatekeys/agent.sock"))
        XCTAssertTrue(AgentSocketPath.fits(String(repeating: "a", count: 103)))
        XCTAssertFalse(AgentSocketPath.fits(String(repeating: "a", count: 104)), "sun_path holds 104 bytes with its NUL")
        let server = AgentSocketServer(backend: RecordingBackend())
        XCTAssertEqual(server.start(path: "/" + String(repeating: "b", count: 120)), .pathTooLong)
        XCTAssertEqual(server.status, .pathTooLong)
    }

    // MARK: socket

    private func connect(_ path: String) -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b } }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(result, 0)
        return fd
    }

    private nonisolated static func roundTrip(_ fd: Int32, _ frame: [UInt8]) -> [UInt8]? {
        guard frame.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress!, frame.count) }) == frame.count else { return nil }
        func read(_ count: Int) -> [UInt8]? {
            var out = [UInt8](repeating: 0, count: count)
            var done = 0
            while done < count {
                let n = out.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress! + done, count - done) }
                if n <= 0 { return nil }
                done += n
            }
            return out
        }
        guard let header = read(4), let length = try? SSHAgentCodec.bodyLength(header: header), let body = read(length) else { return nil }
        return header + body
    }

    func testSocketServesFramesWithMode0600AndRemovesItsFile() async throws {
        let path = dir.appendingPathComponent("agent.sock").path
        try XCTSkipUnless(AgentSocketPath.fits(path), "the temporary folder's path is too long for a socket")
        let server = AgentSocketServer(backend: RecordingBackend())
        XCTAssertEqual(server.start(path: path), .running)
        let info = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((info[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        // A second server finds the socket alive and leaves it alone.
        XCTAssertEqual(AgentSocketServer(backend: RecordingBackend()).start(path: path), .unavailable)
        let fd = connect(path)
        defer { close(fd) }
        let request = try SSHAgentCodec.encode(SSHAgentMessage(type: SSHAgentProtocol.requestIdentities))
        let reply = await Task.detached { DeveloperTests.roundTrip(fd, request) }.value
        XCTAssertEqual(try reply.map(SSHAgentCodec.decode)?.identities, [SSHAgentIdentity(blob: [7], comment: "laptop")])
        // An unsupported request gets FAILURE on the same connection.
        let add = await Task.detached { DeveloperTests.roundTrip(fd, [0, 0, 0, 1, 17]) }.value
        XCTAssertEqual(add, [0, 0, 0, 1, SSHAgentProtocol.failure])
        server.stop()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertEqual(server.status, .stopped)
    }

    // MARK: keys and approvals

    private func addSSHKey(_ store: DevMemoryStore, title: String, privateKey: String, publicKey: String) throws -> String {
        var snap = try store.load()
        let record: [String: JSONValue] = [
            "id": .string(EditorModel.uuid4(SystemRandomSource())), "kind": .string("ssh_key"), "title": .string(title),
            "payload": .object(["private_key": .string(privateKey), "public_key": .string(publicKey)]),
            "created_at": .int(1), "updated_at": .int(1), "favorite": .bool(false), "tags": .array([]),
        ]
        let id = try XCTUnwrap(ImportReviewModel.put(record, ns: .item, into: &snap, isNew: true))
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
        return id
    }

    private func makeAgent(_ store: DevMemoryStore, unlocked: @escaping () -> Bool = { true }) -> MacSSHAgent {
        let agent = MacSSHAgent(defaults: defaults, store: { unlocked() ? store : nil }, socketPath: nil)
        agent.bringForward = {}
        return agent
    }

    private func publicLine(_ name: String) throws -> String {
        try vector("\(name).pub").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func testOfferedKeysFollowTheSettingTheAllowListAndTheLock() throws {
        let store = DevMemoryStore()
        let ed = try addSSHKey(store, title: "Laptop", privateKey: try vector("ed25519.key"), publicKey: try publicLine("ed25519"))
        let rsa = try addSSHKey(store, title: "Server", privateKey: try vector("rsa3072.key"), publicKey: try publicLine("rsa3072"))
        let locked = try addSSHKey(store, title: "Encrypted", privateKey: try vector("ecdsa256_enc.key"), publicKey: "")
        let pemText = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
        let pem = try addSSHKey(store, title: "Old PEM", privateKey: pemText, publicKey: try publicLine("ecdsa256"))
        var unlocked = true
        let agent = makeAgent(store, unlocked: { unlocked })
        DeveloperSettings.setOffered(rsa, true, defaults: defaults)
        DeveloperSettings.setOffered(ed, true, defaults: defaults)
        DeveloperSettings.setOffered(locked, true, defaults: defaults)
        DeveloperSettings.setOffered(pem, true, defaults: defaults)
        XCTAssertEqual(agent.offeredKeys(), [], "the agent is off by default")
        defaults.set(true, forKey: DeveloperSettings.agentKey)
        XCTAssertEqual(agent.offeredKeys().map(\.id), [rsa, ed], "allow-list order; no public half or encrypted PEM: not offered")
        let settings = DeveloperSettingsModel(agent: agent)
        settings.refresh()
        let pemRow = try XCTUnwrap(settings.keys.first { $0.id == pem })
        XCTAssertNil(pemRow.publicKey, "an encrypted PEM key can't be offered, even with its public half")
        XCTAssertEqual(pemRow.reason, "This key format is not supported by the agent")
        XCTAssertEqual(settings.keys.first { $0.id == locked }?.reason,
                       "This key is encrypted. Save its passphrase with the key to offer it.")
        XCTAssertEqual(agent.offeredKeys().first?.comment, "test-only rsa3072", "the public key's own comment, not the title")
        DeveloperSettings.setOffered(rsa, false, defaults: defaults)
        XCTAssertEqual(agent.offeredKeys().map(\.id), [ed])
        unlocked = false
        XCTAssertEqual(agent.offeredKeys(), [], "a locked vault lists nothing")
    }

    /// Waits (in real time: a queued request polls every 50 ms) until a prompt other than `previous` is up.
    private func waitForPrompt(_ gate: StrictItemGate, other previous: UUID? = nil) async {
        var spins = 0
        while (gate.pending == nil || gate.pending?.id == previous) && spins < 400 {
            try? await Task.sleep(for: .milliseconds(10))
            spins += 1
        }
    }

    private func approvalFixture(clock: @escaping () -> Date = Date.init) throws
        -> (MacSSHAgent, StrictItemGate, DevFakeVault, [UInt8]) {
        let store = DevMemoryStore()
        let id = try addSSHKey(store, title: "Laptop", privateKey: try vector("ed25519.key"), publicKey: try publicLine("ed25519"))
        defaults.set(true, forKey: DeveloperSettings.agentKey)
        DeveloperSettings.setOffered(id, true, defaults: defaults)
        let agent = makeAgent(store)
        let vault = DevFakeVault()
        let gate = StrictItemGate(passwords: vault, now: clock)
        agent.attach(gate)
        let blob = try XCTUnwrap(SSHKey.publicLineBlob(try publicLine("ed25519"))).blob
        return (agent, gate, vault, blob)
    }

    func testSignatureApprovalAsksEachTimeUnlessRememberIsTicked() async throws {
        var clock = Date(timeIntervalSince1970: 1_000)
        let (agent, gate, vault, blob) = try approvalFixture(clock: { clock })
        let ssh = SSHAgentPeer(pid: 42, path: "/usr/bin/ssh")

        // Not ticked (the default): approved once, asked again next time.
        let first = Task { await agent.approveAndFetch(blob: blob, peer: ssh, host: "example.org") }
        await waitForPrompt(gate)
        XCTAssertEqual(gate.pending?.level, .approval)
        XCTAssertEqual(gate.pending?.title, "Laptop")
        XCTAssertEqual(gate.pending?.offersRemember, true)
        XCTAssertFalse(gate.rememberApproval, "Remember is off by default")
        XCTAssertTrue(gate.pending?.action.contains("ssh") ?? false)
        XCTAssertTrue(gate.pending?.action.contains("example.org") ?? false)
        await gate.submit(vault.right)
        let secret = await first.value
        XCTAssertEqual(secret?.privateKey, try vector("ed25519.key"))
        let second = Task { await agent.approveAndFetch(blob: blob, peer: ssh, host: nil) }
        await waitForPrompt(gate)
        XCTAssertNotNil(gate.pending, "not remembered without the tick")
        XCTAssertFalse(gate.rememberApproval, "the tick starts off again")
        // Ticked: the same program and key are not asked again for 10 minutes.
        gate.rememberApproval = true
        await gate.submit(vault.right)
        let secondSecret = await second.value
        XCTAssertNotNil(secondSecret)
        let again = await agent.approveAndFetch(blob: blob, peer: ssh, host: nil)
        XCTAssertNotNil(again)
        XCTAssertNil(gate.pending)
        // A program whose path can't be read has no Remember choice; cancelling refuses.
        let unknown = Task { await agent.approveAndFetch(blob: blob, peer: .unknown, host: nil) }
        await waitForPrompt(gate)
        XCTAssertEqual(gate.pending?.offersRemember, false)
        gate.cancel()
        let refused = await unknown.value
        XCTAssertNil(refused)
        // After 10 minutes it asks again; locking drops the prompt and the remembered approvals.
        clock = clock.addingTimeInterval(StrictItemGate.sshRememberSeconds + 1)
        let later = Task { await agent.approveAndFetch(blob: blob, peer: ssh, host: nil) }
        await waitForPrompt(gate)
        XCTAssertNotNil(gate.pending)
        gate.lockReset()
        let afterLock = await later.value
        XCTAssertNil(afterLock, "locking drops the prompt")
    }

    func testSSHApprovalsWaitInLineAndAStrictPromptWithdrawsThem() async throws {
        let (agent, gate, vault, blob) = try approvalFixture()
        let git = SSHAgentPeer(pid: 7, path: "/usr/bin/git")
        let first = Task { await agent.approveAndFetch(blob: blob, peer: git, host: nil) }
        await waitForPrompt(gate)
        let firstID = try XCTUnwrap(gate.pending?.id)
        let second = Task { await agent.approveAndFetch(blob: blob, peer: git, host: nil) }
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertEqual(gate.pending?.id, firstID, "the second request waits; no stacked prompts")
        await gate.submit(vault.right)
        let firstResult = await first.value
        XCTAssertNotNil(firstResult)
        await waitForPrompt(gate, other: firstID)
        XCTAssertEqual(gate.pending?.level, .approval, "the queued request asks once the first is done")
        // A strict-item prompt replaces the SSH approval, which answers "no" at once (FAILURE to the client).
        let strict = VaultItem(id: "s", record: ["kind": .string("web"), "title": .string("Bank"), "username": .string("alex"), "password": .string("pw"),
                                                 "policy": .object(["require_master_password": .bool(true)])])!
        gate.release(strict, action: "Copy password") {}
        XCTAssertEqual(gate.pending?.level, .strict)
        let secondResult = await second.value
        XCTAssertNil(secondResult)
        gate.cancel()
    }

    func testACancelledRequestWithdrawsItsSheet() async throws {
        let (agent, gate, _, blob) = try approvalFixture()
        let task = Task { await agent.approveAndFetch(blob: blob, peer: .unknown, host: nil) }
        await waitForPrompt(gate)
        XCTAssertNotNil(gate.pending)
        task.cancel()
        let result = await task.value
        XCTAssertNil(result)
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertNil(gate.pending, "the agent's deadline takes the sheet down")
    }

    func testAKeySwitchedOffDuringThePromptIsNotSigned() async throws {
        let store = DevMemoryStore()
        let id = try addSSHKey(store, title: "Laptop", privateKey: try vector("ed25519.key"), publicKey: try publicLine("ed25519"))
        defaults.set(true, forKey: DeveloperSettings.agentKey)
        DeveloperSettings.setOffered(id, true, defaults: defaults)
        let agent = makeAgent(store)
        let vault = DevFakeVault()
        let gate = StrictItemGate(passwords: vault)
        agent.attach(gate)
        let blob = try XCTUnwrap(SSHKey.publicLineBlob(try publicLine("ed25519"))).blob
        let task = Task { await agent.approveAndFetch(blob: blob, peer: SSHAgentPeer(pid: 1, path: "/usr/bin/git"), host: nil) }
        await waitForPrompt(gate)
        DeveloperSettings.setOffered(id, false, defaults: defaults)
        await gate.submit(vault.right)
        let result = await task.value
        XCTAssertNil(result)
        // No window (locked): refused without a prompt.
        agent.detach(gate)
        DeveloperSettings.setOffered(id, true, defaults: defaults)
        let noWindow = await agent.approveAndFetch(blob: blob, peer: .unknown, host: nil)
        XCTAssertNil(noWindow)
    }

    func testBackendRefusesSHA1AndUnknownKeyTypesWithoutAsking() async {
        let backend = MacSSHAgentBackend(agent: makeAgent(DevMemoryStore()))
        let rsaBlob = SSHWire.string("ssh-rsa") + SSHWire.mpint([1, 0, 1]) + SSHWire.mpint([0xC5])
        let dssBlob = SSHWire.string("ssh-dss") + SSHWire.string([1])
        let results = await Task.detached {
            [backend.sign(blob: rsaBlob, data: [1], flags: 0, peer: .unknown, boundHost: nil),
             backend.sign(blob: dssBlob, data: [1], flags: 0, peer: .unknown, boundHost: nil)]
        }.value
        XCTAssertEqual(results, [nil, nil])
    }

    // MARK: scan

    @discardableResult
    private func write(_ relative: String, _ text: String) throws -> URL {
        let url = dir.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(text.utf8).write(to: url)
        return url
    }

    private func paths(_ findings: [SecretScanner.Finding]) -> Set<String> {
        Set(findings.map { String($0.url.standardizedFileURL.path.dropFirst(dir.standardizedFileURL.path.count + 1)) })
    }

    func testScanFollowsTheWindowsRules() throws {
        try write("app/.env", "A=1\nB=two\n")
        try write("app/.env.local", "TOKEN=abc\n")
        try write("app/.env.example", "TOKEN=changeme\n")
        try write("app/env.txt", "A=1\n")
        try write("empty/.env", "# only a comment\nEMPTY=\n")
        try write("refs/.env", "A=lgk://x/A\n")
        for skipped in ["node_modules", ".git", "venv", ".venv", "Library", ".hidden", "AppData"] {
            try write("\(skipped)/proj/.env", "A=1\n")
        }
        try write("a/b/c/d/.env", "A=1\n")
        try write("a/b/c/d/e/.env", "A=1\n")
        try write(".ssh/id_ed25519", try vector("ed25519.key"))
        try write(".ssh/id_ed25519.pub", try publicLine("ed25519"))
        try write(".ssh/config", "Host *\n")
        try write("big/.env", "A=" + String(repeating: "x", count: SecretScanner.maxFileBytes) + "\n")
        try FileManager.default.createSymbolicLink(at: dir.appendingPathComponent("link"), withDestinationURL: dir.appendingPathComponent("app"))
        let found = SecretScanner.scan(root: dir)
        XCTAssertEqual(paths(found), ["app/.env", "app/.env.local", "a/b/c/d/.env", ".ssh/id_ed25519"])
        XCTAssertEqual(found.first { $0.url.lastPathComponent == "id_ed25519" }?.keyFormat, "openssh")
        XCTAssertEqual(found.first { $0.url.path.hasSuffix("app/.env") }?.varCount, 2)
        XCTAssertEqual(paths(SecretScanner.scan(root: dir, maxDepth: 1)), ["app/.env", "app/.env.local", ".ssh/id_ed25519"])
        XCTAssertEqual(SecretScanner.scan(root: dir, isCancelled: { true }), [])
    }

    func testEnvParsingMatchesWindows() {
        let text = "# comment\r\n\r\nexport A=1\r\nB = 'two words'\r\n  C=\"x#y\"  # note\r\nD=plain # tail\r\nE=\r\nnot an assignment\r\nF=last"
        let lines = EnvFile.parse(text)
        XCTAssertEqual(lines.map(\.raw).joined(), text)
        let byKey = Dictionary(lines.compactMap { line in line.key.map { ($0, line) } }, uniquingKeysWith: { a, _ in a })
        XCTAssertEqual(byKey["A"]?.value, "1")
        XCTAssertEqual(byKey["B"]?.value, "two words")
        XCTAssertEqual(byKey["C"]?.value, "x#y")
        XCTAssertEqual(byKey["C"]?.trailing, true)
        XCTAssertEqual(byKey["D"]?.value, "plain")
        XCTAssertEqual(byKey["D"]?.trailing, true)
        XCTAssertEqual(byKey["E"]?.value, "")
        XCTAssertEqual(byKey["F"]?.value, "last")
        let multi = EnvFile.parse("KEY=\"line one\nline two\"\nNEXT=1\n")
        XCTAssertEqual(multi.first?.value, "line one\nline two")
        XCTAssertEqual(multi.last?.key, "NEXT")
        let comments = EnvFile.parse("KEY= #comment\nOTHER=\t#tab comment\nPLAIN=x #c\n")
        XCTAssertEqual(comments.map(\.key), ["KEY", "OTHER", "PLAIN"])
        XCTAssertEqual(comments.map(\.value), ["", "", "x"])
        XCTAssertEqual(comments.map(\.trailing), [true, true, true])
        XCTAssertEqual(EnvFile.plainVariableCount("KEY= #comment\n"), 0)
        let escaped = "PEM=\"-----BEGIN KEY-----\\nMIIE\\n-----END KEY-----\"\nSINGLE='a\\nb'\nPLAIN=\"no escapes\"\nPATH_=C:\\dir\n"
        XCTAssertEqual(Set(EnvFile.referenceable(escaped).map(\.name)), ["SINGLE", "PLAIN", "PATH_"])
        let limits = "A=1\nB=lgk://x/B\nC=\nD=3 # c\nD=4\nE=" + String(repeating: "x", count: 5000) + "\n"
            + (0..<60).map { "V\($0)=v\n" }.joined()
        let names = EnvFile.referenceable(limits).map(\.name)
        XCTAssertTrue(names.contains("A"))
        XCTAssertFalse(names.contains("B") || names.contains("C") || names.contains("D") || names.contains("E"))
        XCTAssertEqual(names.count, EnvFile.maxFields)
    }

    func testImportCopiesIntoTheVaultOnceAndNeverTouchesTheFiles() async throws {
        let env = try write("proj/.env", "API_KEY=abc123\nexport DB=\"postgres://x\" # main\n")
        let key = try write(".ssh/id_ed25519", try vector("ed25519.key"))
        let before = try [Data(contentsOf: env), Data(contentsOf: key)]
        let store = DevMemoryStore()
        let model = SecretScanModel(store: { store }, isPro: { true }, defaults: defaults, bookmarks: PathBookmarks(),
                                    clock: FixedClock())
        model.setFolder(dir)
        await model.scan()?.value
        XCTAssertEqual(model.findings.count, 2)
        XCTAssertEqual(model.selected.count, 2)
        model.importSelected()
        XCTAssertEqual(try [Data(contentsOf: env), Data(contentsOf: key)], before)
        let items = VaultItem.items(from: try store.load())
        XCTAssertEqual(items.count, 2)
        let ssh = try XCTUnwrap(items.first { $0.kind == "ssh_key" })
        XCTAssertEqual(ssh.title, "id_ed25519")
        let payload = try XCTUnwrap(ssh.record["payload"]?.objectValue)
        XCTAssertEqual(payload["public_key"]?.stringValue,
                       try SSHKey.load(try vector("ed25519.key"), passphrase: nil).publicLine(comment: "id_ed25519"))
        let note = try XCTUnwrap(items.first { $0.kind == "note" })
        XCTAssertEqual(note.title, "proj/.env")
        let fields = note.record["payload"]?.objectValue?["fields"]?.arrayValue ?? []
        XCTAssertEqual(fields.compactMap { $0.objectValue?["name"]?.stringValue }, ["API_KEY"], "a value with a comment stays in the text only")
        // Scanning and importing again adds nothing.
        await model.scan()?.value
        XCTAssertEqual(model.imported.count, 2)
        XCTAssertTrue(model.selected.isEmpty)
        model.selected = Set(model.findings.map(\.id))
        model.importSelected()
        XCTAssertEqual(VaultItem.items(from: try store.load()).count, 2)
    }

    func testImportStopsAtTheFreePlanLimit() async throws {
        try write("one/.env", "A=1\n")
        try write("two/.env", "B=2\n")
        let store = DevMemoryStore()
        for n in 0..<(ItemLimit.freeItems - 1) {
            _ = try addSSHKey(store, title: "k\(n)", privateKey: try vector("ed25519.key"), publicKey: "")
        }
        var needsPro = 0
        let model = SecretScanModel(store: { store }, isPro: { false }, defaults: defaults, bookmarks: PathBookmarks(),
                                    clock: FixedClock())
        model.onNeedsPro = { needsPro += 1 }
        model.setFolder(dir)
        await model.scan()?.value
        model.importSelected()
        XCTAssertEqual(ItemLimit.liveCount(try store.load()), ItemLimit.freeItems)
        XCTAssertEqual(needsPro, 1)
        XCTAssertEqual(model.imported.count, 1)
    }
}
