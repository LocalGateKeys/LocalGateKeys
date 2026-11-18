import Foundation
import Darwin
import LGKCore
import AppSharedMac

// The Mac's SSH agent socket (Windows `ssh_agent/server.py`): a Unix socket `agent.sock` in the app-group container,
// mode 0600. A connection stays open (ssh sends several requests on one connection) and is served on its own thread,
// one frame at a time; at most 16 at once, and a client beyond that is closed at once. A connection with no request
// for 300 s is closed, so idle clients cannot hold every slot.
//
// A connection bound with `session-bind@openssh.com` remembers the host for the prompt. A connection that was ever
// bound for forwarding (`ssh -A`) lists nothing and signs nothing: the vault's keys are never served to other hosts.

/// Where the socket lives. macOS limits a socket path to 104 bytes (`sun_path`), the terminating NUL included.
enum AgentSocketPath {
    static let fileName = "agent.sock"
    static let maxPathBytes = 104

    /// `<app-group container>/agent.sock`, or nil without the container (unsigned builds, tests).
    static func defaultURL() -> URL? { AppGroup.containerURL?.appendingPathComponent(fileName, isDirectory: false) }

    static func fits(_ path: String) -> Bool { path.utf8.count < maxPathBytes }
}

/// The program at the other end of a connection: `LOCAL_PEERPID`, then `proc_pidpath` when the sandbox allows it.
struct SSHAgentPeer: Equatable, Sendable {
    let pid: Int32?
    let path: String?

    static let unknown = SSHAgentPeer(pid: nil, path: nil)

    /// "ssh", "git", … or "a program" when the path cannot be read (it reads "Allow a program to use this SSH key").
    var displayName: String {
        guard let path, !path.isEmpty else { return String(localized: "ssh_agent.unknownProgram", defaultValue: "a program") }
        return URL(fileURLWithPath: path).lastPathComponent
    }

    static func of(socket fd: Int32) -> SSHAgentPeer {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid > 0 else { return .unknown }
        var buffer = [CChar](repeating: 0, count: 4 * 1024)   // PROC_PIDPATHINFO_MAXSIZE
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return SSHAgentPeer(pid: pid, path: nil) }
        let path = String(decoding: buffer.prefix(Int(length)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return SSHAgentPeer(pid: pid, path: path)
    }
}

/// What the socket serves (Windows `SshAgentService`); called from connection threads, never the main thread.
protocol SSHAgentBackend: Sendable {
    /// Allow-listed keys while unlocked; never prompts.
    func identities() -> [SSHAgentIdentity]
    /// The signature blob, or nil (FAILURE) when refused, locked, not offered or past the deadline.
    func sign(blob: [UInt8], data: [UInt8], flags: UInt32, peer: SSHAgentPeer, boundHost: String?) -> [UInt8]?
    func verifyBind(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8]) -> Bool
    func hostName(for hostKey: [UInt8]) -> String
}

/// One connection's session-bind state (Windows `_Connection`).
struct SSHAgentConnectionState: Equatable, Sendable {
    var peer: SSHAgentPeer = .unknown
    var bound = false
    var forwarding = false
    var boundHost: String?
}

/// Windows `SshAgentServer._reply`: the answer to one request.
enum SSHAgentReplies {
    static func reply(to message: SSHAgentMessage, state: inout SSHAgentConnectionState,
                      backend: any SSHAgentBackend) -> SSHAgentMessage {
        switch message.type {
        case SSHAgentProtocol.requestIdentities:
            return SSHAgentMessage(type: SSHAgentProtocol.identitiesAnswer, identities: state.forwarding ? [] : backend.identities())
        case SSHAgentProtocol.signRequest:
            if state.forwarding { return SSHAgentMessage(type: SSHAgentProtocol.failure) }
            guard let signature = backend.sign(blob: message.keyBlob, data: message.data, flags: message.flags,
                                               peer: state.peer, boundHost: state.boundHost) else {
                return SSHAgentMessage(type: SSHAgentProtocol.failure)
            }
            return SSHAgentMessage(type: SSHAgentProtocol.signResponse, signature: signature)
        case SSHAgentProtocol.extensionRequest:
            guard let bind = message.bind else { return SSHAgentMessage(type: SSHAgentProtocol.failure) }
            // Fail closed, before anything else: ssh keeps forwarding after a refused bind, so a forwarding bind marks
            // the connection even when its host signature cannot be checked. Once forwarded, always forwarded.
            state.forwarding = state.forwarding || bind.forwarding
            if state.bound { return SSHAgentMessage(type: SSHAgentProtocol.failure) }   // one bind per connection
            guard backend.verifyBind(hostKey: bind.hostKey, sessionID: bind.sessionID, signature: bind.signature) else {
                return SSHAgentMessage(type: SSHAgentProtocol.failure)   // only the host name depends on the signature
            }
            state.bound = true
            let name = backend.hostName(for: bind.hostKey)
            state.boundHost = name.isEmpty ? nil : name
            return SSHAgentMessage(type: SSHAgentProtocol.success)
        default:
            return SSHAgentMessage(type: SSHAgentProtocol.failure)   // ADD/REMOVE identity, LOCK, smartcard, …
        }
    }
}

/// Windows `service.host_name_for`: the first unhashed `known_hosts` name for a host key, else its fingerprint.
enum KnownHosts {
    static let maxBytes = 4 * 1024 * 1024

    static func name(for hostKey: [UInt8], knownHosts text: String?) -> String {
        guard let text else { return SSHKey.fingerprint(of: hostKey) }
        let encoded = Data(hostKey).base64EncodedString()
        for line in text.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard fields.count >= 3, !fields[0].hasPrefix("#"), !fields[0].hasPrefix("@"), !fields[0].hasPrefix("|") else {
                continue   // comments, @revoked / @cert-authority, hashed names
            }
            guard fields[2] == encoded else { continue }
            for name in fields[0].split(separator: ",") {
                if name.isEmpty || name.hasPrefix("!") || name.contains("*") || name.contains("?") { continue }
                if name.hasPrefix("["), let close = name.range(of: "]:") {
                    let host = name[name.index(after: name.startIndex)..<close.lowerBound]
                    let port = name[close.upperBound...]
                    return port == "22" ? String(host) : "\(host):\(port)"
                }
                return String(name)
            }
        }
        return SSHKey.fingerprint(of: hostKey)
    }

    /// The user's real `~/.ssh/known_hosts` (outside the sandbox container), when the sandbox lets the app read it.
    static func read() -> String? {
        guard let entry = getpwuid(getuid()), let dir = entry.pointee.pw_dir else { return nil }
        let url = URL(fileURLWithPath: String(cString: dir)).appendingPathComponent(".ssh/known_hosts")
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: maxBytes) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}

/// The listening socket and its connections. Thread-safe: state is guarded by `lock`; each connection runs on its
/// own thread and the accept loop on a private dispatch queue.
final class AgentSocketServer: @unchecked Sendable {
    enum Status: Equatable, Sendable {
        case stopped, running
        /// The container path is longer than a socket path may be.
        case pathTooLong
        /// No app-group container, the socket could not be made, or another copy of the app already serves it.
        case unavailable
    }

    static let maxConnections = 16
    static let idleTimeout: TimeInterval = 300

    private let backend: any SSHAgentBackend
    private let idleTimeout: TimeInterval
    private let queue = DispatchQueue(label: "app.localgatekeys.ssh-agent")
    private let lock = NSLock()
    private var source: DispatchSourceRead?
    private var listener: Int32 = -1
    private var socketPath: String?
    private var socketInode: ino_t = 0
    private var clients: Set<Int32> = []
    private var stopping = false
    private var currentStatus: Status = .stopped

    init(backend: any SSHAgentBackend, idleTimeout: TimeInterval = AgentSocketServer.idleTimeout) {
        self.backend = backend
        self.idleTimeout = idleTimeout
    }

    deinit { stop() }

    var status: Status { locked { currentStatus } }

    var activeConnections: Int { locked { clients.count } }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }

    // MARK: lifecycle

    /// Listens on `path`; the result is also `status`. A socket left by a crash is replaced; one another process
    /// still answers on is left alone (`unavailable`).
    @discardableResult
    func start(path: String) -> Status {
        stop()
        guard AgentSocketPath.fits(path) else { return setStatus(.pathTooLong) }
        if Self.isLiveSocket(path) { return setStatus(.unavailable) }
        Self.removeStaleSocket(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return setStatus(.unavailable) }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var address = Self.address(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        var info = stat()
        // 0600 before listen(): the container folder is the user's alone, and the socket answers no one until listen.
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

    /// Stops listening, removes the socket file (if it is still ours) and ends every connection. An answer that
    /// was waiting for a prompt is not sent.
    func stop() {
        let (source, path, inode) = locked { () -> (DispatchSourceRead?, String?, ino_t) in
            stopping = true
            // Under the lock: a connection thread removes its fd here before closing it, so no fd is reused meanwhile.
            // shutdown wakes the blocked read; the connection thread then closes the fd.
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
    private func setStatus(_ status: Status) -> Status {
        locked { currentStatus = status }
        return status
    }

    private static func address(_ path: String) -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            for (i, byte) in bytes.enumerated() where i < raw.count - 1 { raw[i] = byte }
        }
        return address
    }

    /// True when something accepts connections at `path` (another copy of the app).
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

    /// Removes a dead socket file at `path`; any other kind of file is left alone (bind then fails).
    private static func removeStaleSocket(_ path: String) {
        var info = stat()
        if lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFSOCK { unlink(path) }
    }

    // MARK: connections

    private func acceptPending() {
        while true {
            let fd = locked { listener }
            guard fd >= 0 else { return }
            let client = Darwin.accept(fd, nil, nil)
            guard client >= 0 else { return }   // EAGAIN: nothing more waiting
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            _ = fcntl(client, F_SETFL, fcntl(client, F_GETFL) & ~O_NONBLOCK)
            var on: Int32 = 1
            _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            var timeout = timeval(tv_sec: Int(idleTimeout), tv_usec: Int32((idleTimeout - idleTimeout.rounded(.down)) * 1_000_000))
            _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
            let accepted = locked { () -> Bool in
                guard !stopping, clients.count < Self.maxConnections else { return false }
                clients.insert(client)
                return true
            }
            guard accepted else { close(client); continue }
            let peer = SSHAgentPeer.of(socket: client)
            let thread = Thread { [self] in serve(client, peer: peer) }
            thread.name = "lgk-ssh-agent-client"
            thread.start()
        }
    }

    private func serve(_ fd: Int32, peer: SSHAgentPeer) {
        defer {
            locked {   // removed and closed under the lock, so stop() never shuts down a reused fd
                _ = clients.remove(fd)
                close(fd)
            }
        }
        var state = SSHAgentConnectionState(peer: peer)
        while !locked({ stopping }) {
            guard let header = Self.read(fd, count: 4) else { return }   // closed, idle for 300 s, or stopped
            guard let length = try? SSHAgentCodec.bodyLength(header: header), let body = Self.read(fd, count: length),
                  let message = try? SSHAgentCodec.decode(header + body) else { return }   // bad frame: closed, no reply
            if locked({ stopping }) { return }
            let reply = SSHAgentReplies.reply(to: message, state: &state, backend: backend)
            if locked({ stopping }) { return }   // turned off while a prompt was open: the answer is not sent
            guard let frame = try? SSHAgentCodec.encode(reply), Self.write(fd, frame) else { return }
        }
    }

    /// Exactly `count` bytes, or nil at end of file, on the idle timeout or on an error.
    private static func read(_ fd: Int32, count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var done = 0
        while done < count {
            let n = buffer.withUnsafeMutableBytes { raw in Darwin.read(fd, raw.baseAddress! + done, count - done) }
            if n > 0 { done += n; continue }
            if n < 0 && errno == EINTR { continue }
            return nil
        }
        return buffer
    }

    private static func write(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
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
