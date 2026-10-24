import Foundation
import os

/// DEBUG builds only: a step-by-step trace of the AutoFill extension (and the app's view of it), appended to
/// `<app group>/Diagnostics/autofill-trace.log` and sent to `os_log` (subsystem `app.localgatekeys.autofill`).
///
/// Never a secret. A `TraceMessage` interpolates only redacted values: a record id as its last 6 characters
/// (`rid:`), a URL or domain as its host (`host:`), an error as its type, domain and code (`error:`), numbers,
/// booleans and type names. Plain `String` interpolation does not compile, so a username, password, TOTP
/// secret or key cannot be traced by accident; fixed text goes in through `name:` as a `StaticString`.
///
/// In a Release build `AutoFillTrace.log` is an empty inline function and nothing below the `#if` exists.
public enum AutoFillTrace {
    @inline(__always)
    public static func log(_ message: @autoclosure () -> TraceMessage) {
        #if DEBUG
        AutoFillTraceWriter.shared.append(message().text)
        #endif
    }
}

/// A trace line built only from redacted parts (see `AutoFillTrace`).
public struct TraceMessage: ExpressibleByStringInterpolation, Sendable {
    public let text: String

    public init(stringLiteral value: StaticString) { text = value.description }
    public init(stringInterpolation: Interpolation) { text = stringInterpolation.text }

    public struct Interpolation: StringInterpolationProtocol {
        var text = ""
        public init(literalCapacity: Int, interpolationCount: Int) { text.reserveCapacity(literalCapacity + 16 * interpolationCount) }
        public mutating func appendLiteral(_ literal: StaticString) { text += literal.description }

        /// A record identifier: its last 6 characters only.
        public mutating func appendInterpolation(rid: String?) { text += TraceRedact.recordID(rid) }
        /// A URL, origin or bare domain: its host only (no scheme, path, query, user info or port).
        public mutating func appendInterpolation(host: String?) { text += TraceRedact.host(host) }
        public mutating func appendInterpolation(hosts: [String]) { text += "[" + hosts.map(TraceRedact.host).joined(separator: ",") + "]" }
        /// An error: type, domain and code (LAError, ASExtensionError, KeychainVaultError status, ...), no message.
        public mutating func appendInterpolation(error: (any Error)?) { text += TraceRedact.error(error) }
        /// A type's name, e.g. the request class.
        public mutating func appendInterpolation(type: Any.Type) { text += String(describing: type) }
        /// Fixed text chosen in code (method or step names, enum cases spelled at the call site).
        public mutating func appendInterpolation(name: StaticString) { text += name.description }
        public mutating func appendInterpolation<I: BinaryInteger>(_ n: I) { text += String(n) }
        public mutating func appendInterpolation(_ b: Bool) { text += b ? "true" : "false" }
        public mutating func appendInterpolation(_ d: Double) { text += String(format: "%.3f", d) }
        /// Another already-redacted message.
        public mutating func appendInterpolation(_ m: TraceMessage) { text += m.text }
        /// An object's identity (which instance), never its contents.
        public mutating func appendInterpolation(instance o: AnyObject?) {
            text += o.map { String(UInt(bitPattern: ObjectIdentifier($0).hashValue) & 0xFFFFFF, radix: 16) } ?? "nil"
        }
    }
}

/// The redaction rules `TraceMessage` applies.
public enum TraceRedact {
    public static func recordID(_ id: String?) -> String {
        guard let id else { return "nil" }
        guard !id.isEmpty else { return "<empty>" }
        return "…" + String(id.suffix(6)) + "(len \(id.count))"
    }

    public static func host(_ s: String?) -> String {
        guard let s else { return "nil" }
        guard !s.isEmpty else { return "<empty>" }
        let withScheme = s.contains("://") ? s : "https://" + s
        if let h = URLComponents(string: withScheme)?.host, !h.isEmpty { return h.lowercased() }
        return "<unparsed len \(s.count)>"
    }

    public static func error(_ e: (any Error)?) -> String {
        guard let e else { return "nil" }
        let ns = e as NSError
        return "\(String(describing: type(of: e)))(\(ns.domain) \(ns.code))"
    }
}

#if DEBUG
/// The trace file: timestamped lines, rotated to `autofill-trace.1.log` when the current file passes
/// `maxBytes` (one older generation kept, so at most about `2 * maxBytes` on disk).
public final class AutoFillTraceWriter: @unchecked Sendable {
    public static let fileName = "autofill-trace.log"
    public static let rotatedName = "autofill-trace.1.log"
    public static let subsystem = "app.localgatekeys.autofill"

    /// The app group's `Diagnostics` folder; os_log only when there is no container (unsigned builds, tests).
    public static let shared = AutoFillTraceWriter(
        directory: AppGroup.containerURL?.appendingPathComponent("Diagnostics", isDirectory: true))

    public let directory: URL?
    public let maxBytes: Int
    private let lock = NSLock()
    private let logger = Logger(subsystem: AutoFillTraceWriter.subsystem, category: "trace")
    private let process: String
    private let now: @Sendable () -> Date

    public init(directory: URL?, maxBytes: Int = 100 * 1024, now: @escaping @Sendable () -> Date = Date.init) {
        self.directory = directory; self.maxBytes = maxBytes; self.now = now
        let name = ProcessInfo.processInfo.processName
        process = "\(name)[\(ProcessInfo.processInfo.processIdentifier)]"
    }

    public var fileURL: URL? { directory?.appendingPathComponent(Self.fileName) }
    public var rotatedURL: URL? { directory?.appendingPathComponent(Self.rotatedName) }

    /// Used under `lock` only.
    private let stamp: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    public func append(_ message: String) {
        lock.lock(); defer { lock.unlock() }
        let thread = Thread.isMainThread ? "main" : "bg"
        let line = "\(stamp.string(from: now())) \(process) \(thread) \(message)\n"
        logger.log("\(line, privacy: .public)")
        guard let directory, let url = fileURL, let rotated = rotatedURL else { return }
        let fm = FileManager.default
        try? fm.createDirectory(at: directory, withIntermediateDirectories: true)
        let size = ((try? fm.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.intValue ?? 0
        if size > 0, size + line.utf8.count > maxBytes {
            try? fm.removeItem(at: rotated)
            try? fm.moveItem(at: url, to: rotated)
        }
        if !fm.fileExists(atPath: url.path) { fm.createFile(atPath: url.path, contents: nil) }
        guard let h = try? FileHandle(forWritingTo: url) else { return }
        defer { try? h.close() }
        _ = try? h.seekToEnd()
        try? h.write(contentsOf: Data(line.utf8))
    }

    /// Older generation first, then the current file.
    public func read() -> String {
        lock.lock(); defer { lock.unlock() }
        return [rotatedURL, fileURL].compactMap { $0 }.compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        for u in [rotatedURL, fileURL].compactMap({ $0 }) { try? FileManager.default.removeItem(at: u) }
    }
}
#endif
