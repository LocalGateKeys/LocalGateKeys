import Foundation
import Darwin
import Security
import LGKCore

// The AI agent sockets (Windows: the `lgk` pipe of `cli_service`): Unix sockets in an app-group container, mode 0600,
// separate from the SSH agent's `agent.sock`. One request per connection: a single JSON object on one line (at most
// 1 MiB), one JSON reply line, then the connection closes. At most 16 connections at once (a client beyond that is
// closed at once); a connection that sends nothing for 300 s is closed. Each connection runs on its own thread,
// because an answer can wait for the user's approval.
//
// `mcp.sock` (the app group shared with `lgk`): `lgk mcp` forwards each tool call here.
// `fill.sock` (the Safari app group): the Safari extension asks here for an agent's approved sign-in, and only a
// connection from the Safari extension signed by the same team is served (`AgentPeerCheck`).

/// The program at the other end of an agent connection.
struct AgentPeer: Equatable, Sendable {
    let pid: Int32?
    let path: String?
    /// The peer's parent (`lgk` is started by the agent: the parent is the agent's program).
    let parentPath: String?
    /// The peer's audit token (code-signature checks), when the kernel gave one.
    let auditToken: Data?

    static let unknown = AgentPeer(pid: nil, path: nil, parentPath: nil, auditToken: nil)

    /// What the approval names as the program: the program that started `lgk`, else the peer itself.
    var programName: String {
        let peerName = path.map { URL(fileURLWithPath: $0).lastPathComponent } ?? ""
        if peerName == "lgk", let parentPath, !parentPath.isEmpty { return URL(fileURLWithPath: parentPath).lastPathComponent }
        return peerName
    }

    static func of(socket fd: Int32) -> AgentPeer {
        var token = audit_token_t()
        var tokenSize = socklen_t(MemoryLayout<audit_token_t>.size)
        let audit = getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tokenSize) == 0
            ? withUnsafeBytes(of: &token) { Data($0.prefix(Int(tokenSize))) } : nil
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else {
            return AgentPeer(pid: nil, path: nil, parentPath: nil, auditToken: audit)
        }
        var info = proc_bsdinfo()
        let infoSize = Int32(MemoryLayout<proc_bsdinfo>.size)
        let parent = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, infoSize) == infoSize ? Int32(info.pbi_ppid) : 0
        return AgentPeer(pid: pid, path: Self.path(of: pid), parentPath: parent > 1 ? Self.path(of: parent) : nil,
                         auditToken: audit)
    }

    /// `proc_pidpath`, when the sandbox allows it.
    static func path(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * 1024)   // PROC_PIDPATHINFO_MAXSIZE
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(decoding: buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

/// Whether a peer is our own Safari extension: valid code signature by this app's team, with the extension's bundle
/// identifier. Fails closed (an unsigned build, no team, no audit token).
enum AgentPeerCheck {
    /// The team that signed this app, nil for unsigned or ad-hoc builds.
    static let ownTeam: String? = {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any] else { return nil }
        return values[kSecCodeInfoTeamIdentifier as String] as? String
    }()

    /// `<app bundle id>.safari` (project.yml: `$(BUNDLE_PREFIX).app.safari`).
    static var safariExtensionID: String? { Bundle.main.bundleIdentifier.map { $0 + ".safari" } }

    static func isSafariExtension(_ peer: AgentPeer) -> Bool {
        guard let token = peer.auditToken, let team = ownTeam, let identifier = safariExtensionID,
              team.allSatisfy({ $0.isLetter || $0.isNumber }),
              identifier.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }) else { return false }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: token] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess, let code else { return false }
        var requirement: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else {
            return false
        }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
}

/// One listening agent socket. Thread-safe: state is guarded by `lock`.
final class AgentLineServer: @unchecked Sendable {
    typealias Handler = @Sendable (_ request: [String: JSONValue], _ peer: AgentPeer) -> [String: JSONValue]

    static let maxConnections = 16
    static let idleTimeout: TimeInterval = 300
    static let maxLine = 1 << 20

    private let handler: Handler
    /// Refuses a peer before reading anything (nil: every peer of this user).
    private let admit: (@Sendable (AgentPeer) -> Bool)?
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var source: DispatchSourceRead?
    private var listener: Int32 = -1
    private var socketPath: String?
    private var socketInode: ino_t = 0
    private var clients: Set<Int32> = []
    private var stopping = false
    private var currentStatus: AgentSocketServer.Status = .stopped

    init(label: String, admit: (@Sendable (AgentPeer) -> Bool)? = nil, handler: @escaping Handler) {
        self.queue = DispatchQueue(label: label)
        self.admit = admit
        self.handler = handler
    }

    deinit { stop() }

    var status: AgentSocketServer.Status { locked { currentStatus } }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    @discardableResult
    func start(path: String) -> AgentSocketServer.Status {
        stop()
        guard AgentSocketPath.fits(path) else { return setStatus(.pathTooLong) }
        if Self.isLiveSocket(path) { return setStatus(.unavailable) }
        var old = stat()
        if lstat(path, &old) == 0, (old.st_mode & S_IFMT) == S_IFSOCK { unlink(path) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return setStatus(.unavailable) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var address = Self.address(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        var info = stat()
        guard bound == 0, chmod(path, 0o600) == 0, lstat(path, &info) == 0, listen(fd, 16) == 0 else {
            close(fd)
            if bound == 0 { unlink(path) }
            return setStatus(.unavailable)
        }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.acceptPending() }
        source.setCancelHandler { close(fd) }
        locked {
            stopping = false
            listener = fd
            socketPath = path
            socketInode = info.st_ino
            self.source = source
            currentStatus = .running
        }
        source.resume()
        return .running
    }

    /// Stops listening, removes the socket file (if it is still ours) and ends every connection.
    func stop() {
        let (source, path, inode) = locked { () -> (DispatchSourceRead?, String?, ino_t) in
            stopping = true
            for fd in clients { shutdown(fd, SHUT_RDWR) }
            let result = (self.source, socketPath, socketInode)
            self.source = nil
            listener = -1
            socketPath = nil
            if currentStatus == .running { currentStatus = .stopped }
            return result
        }
        source?.cancel()
        if let path {
            var info = stat()
            if lstat(path, &info) == 0, info.st_ino == inode { unlink(path) }
        }
    }

    @discardableResult
    private func setStatus(_ status: AgentSocketServer.Status) -> AgentSocketServer.Status {
        locked { currentStatus = status }
        return status
    }

    static func address(_ path: String) -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            for (i, byte) in bytes.enumerated() where i < raw.count - 1 { raw[i] = byte }
        }
        return address
    }

    private static func isLiveSocket(_ path: String) -> Bool {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFSOCK else { return false }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var address = Self.address(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        return result == 0
    }

    private func acceptPending() {
        while true {
            let fd = locked { listener }
            guard fd >= 0 else { return }
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { return }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK)
            var on: Int32 = 1
            _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            var timeout = timeval(tv_sec: Int(Self.idleTimeout), tv_usec: 0)
            _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            let accepted = locked { () -> Bool in
                guard !stopping, clients.count < Self.maxConnections else { return false }
                clients.insert(client)
                return true
            }
            guard accepted else { close(client); continue }
            let peer = AgentPeer.of(socket: client)
            let thread = Thread { [self] in serve(client, peer: peer) }
            thread.name = "lgk-agent-client"
            thread.start()
        }
    }

    private func serve(_ fd: Int32, peer: AgentPeer) {
        defer {
            locked {
                _ = clients.remove(fd)
                close(fd)
            }
        }
        if let admit, !admit(peer) { return }
        guard let line = Self.readLine(fd) else { return }
        let reply: [String: JSONValue]
        if case .object(let request)? = try? CanonicalJSON.parse(line) {
            reply = handler(request, peer)
        } else {
            reply = ["ok": .bool(false), "error": .string("bad_request"), "message": .string("The request is malformed.")]
        }
        if locked({ stopping }) { return }   // turned off while a prompt was open: the answer is not sent
        guard let bytes = try? CanonicalJSON.encode(.object(reply), dialect: .utf8) else { return }
        _ = Self.write(fd, bytes + [0x0A])
    }

    /// The bytes before the first newline (or the end of the stream); nil when longer than `maxLine`, on the idle
    /// timeout or an error.
    static func readLine(_ fd: Int32) -> [UInt8]? {
        var line: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = chunk.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n < 0 { return nil }
            if n == 0 { return line.isEmpty ? nil : line }
            if let newline = chunk[0..<n].firstIndex(of: 0x0A) {
                line += chunk[0..<newline]
                return line.count > maxLine ? nil : line
            }
            line += chunk[0..<n]
            if line.count > maxLine { return nil }
        }
    }

    static func write(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var done = 0
        while done < bytes.count {
            let n = bytes.withUnsafeBytes { raw in Darwin.write(fd, raw.baseAddress! + done, bytes.count - done) }
            if n > 0 { done += n; continue }
            if n < 0 && errno == EINTR { continue }
            return false
        }
        return true
    }
}
