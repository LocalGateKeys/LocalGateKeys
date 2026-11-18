import Foundation
import Darwin
import LGKCore

// `lgk` in LocalGateKeys.app/Contents/MacOS: one command, `lgk mcp`, the Model Context Protocol server AI agents start
// (Windows `lgk mcp`). It speaks MCP on stdin/stdout (LGKCore `McpServer`) and forwards each tool call to the running
// app over `mcp.sock` in the app group's container; the app asks the user. It opens no network port, reads no vault
// file and writes nothing to stderr except usage and fatal errors.

let usage = "usage: lgk mcp\n\nStarts the LocalGateKeys MCP server for AI agents (stdio). Turn on Settings > Developer > "
    + "Allow AI agents to use LocalGateKeys in the app first.\n"

/// The app group from the Info.plist embedded in this binary (project.yml: `LGKAppGroup`).
func socketPath() -> String? {
    guard let group = Bundle.main.object(forInfoDictionaryKey: "LGKAppGroup") as? String, !group.isEmpty else { return nil }
    if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) {
        return container.appendingPathComponent("mcp.sock", isDirectory: false).path
    }
    guard let entry = getpwuid(getuid()), let home = entry.pointee.pw_dir else { return nil }
    return URL(fileURLWithPath: String(cString: home)).appendingPathComponent("Library/Group Containers/\(group)/mcp.sock").path
}

struct NotRunning: Error {}

/// One request over `mcp.sock`: a JSON line out, a JSON line back. Waits up to 200 s (an approval takes up to 120 s,
/// a fill up to 60 s).
func forward(_ request: [String: JSONValue], path: String?) throws -> JSONValue {
    guard let path, path.utf8.count < 104 else { throw NotRunning() }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw NotRunning() }
    defer { close(fd) }
    var on: Int32 = 1
    _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    var timeout = timeval(tv_sec: 200, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8)
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
        for (i, byte) in bytes.enumerated() where i < raw.count - 1 { raw[i] = byte }
    }
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
    }
    guard connected == 0 else {
        // The app is not running, or AI agents are off: say how to fix it (McpServer passes this message on).
        return .object(["ok": .bool(false), "error": .string("not_running"),
                        "message": .string("LocalGateKeys did not answer. Start it, unlock it and turn on Settings > "
                                           + "Developer > Allow AI agents to use LocalGateKeys.")])
    }
    let line = try CanonicalJSON.encode(.object(request), dialect: .utf8) + [0x0A]
    var sent = 0
    while sent < line.count {
        let n = line.withUnsafeBytes { write(fd, $0.baseAddress! + sent, line.count - sent) }
        if n < 0 && errno == EINTR { continue }
        guard n > 0 else { throw NotRunning() }
        sent += n
    }
    var reply: [UInt8] = []
    var chunk = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
        let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
        if n < 0 && errno == EINTR { continue }
        guard n >= 0 else { throw NotRunning() }
        if n == 0 { break }
        if let newline = chunk[0..<n].firstIndex(of: 0x0A) { reply += chunk[0..<newline]; break }
        reply += chunk[0..<n]
        if reply.count > McpServer.maxLine { throw NotRunning() }
    }
    return try CanonicalJSON.parse(reply)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments == ["mcp"] else {
    FileHandle.standardError.write(Data(usage.utf8))
    exit(arguments.isEmpty || arguments == ["--help"] || arguments == ["-h"] ? 0 : 2)
}
signal(SIGPIPE, SIG_IGN)
let path = socketPath()
let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
let server = McpServer(forward: { [path] in try forward($0, path: path) }, version: version)
exit(server.serve(input: .standardInput, output: .standardOutput))
