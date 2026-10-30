import Crypto
import Foundation

public enum BreachCheckError: Error, Equatable, LocalizedError {
    case strictOffline, disabled, failed

    public var errorDescription: String? {
        switch self {
        case .strictOffline:
            return String(localized: "Strict offline mode is on. Turn it off in Privacy settings to run an explicit external check.", bundle: .module)
        case .disabled:
            return String(localized: "Breach checks are off. Turning them on lets a check button send a 5-character hash prefix to HIBP. Nothing is checked automatically.", bundle: .module)
        case .failed:
            return String(localized: "Breach check could not complete; no result is available.", bundle: .module)
        }
    }
}

public protocol BreachTransport: Sendable {
    func get(_ url: URL, headers: [String: String]) async throws -> Data
}

/// URLSession transport: 10 s timeout, redirects refused, at most 200000 bytes read.
public final class URLSessionBreachTransport: NSObject, BreachTransport, URLSessionTaskDelegate, @unchecked Sendable {
    public static let maxBytes = 200_000
    private let session: URLSession

    public convenience override init() {
        self.init(configuration: .ephemeral)
    }

    /// `configuration` is for tests (stub protocol classes); timeouts and caching are always set here.
    public init(configuration: URLSessionConfiguration) {
        let config = configuration
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 10
        config.urlCache = nil
        config.httpCookieStorage = nil
        session = URLSession(configuration: config)
        super.init()
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask,
                           willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest) async -> URLRequest? {
        nil
    }

    public func get(_ url: URL, headers: [String: String]) async throws -> Data {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        for (key, value) in headers { request.setValue(value, forHTTPHeaderField: key) }
        let (bytes, response) = try await session.bytes(for: request, delegate: self)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BreachCheckError.failed
        }
        if http.expectedContentLength > Int64(Self.maxBytes) { throw BreachCheckError.failed }
        var data = Data()
        var chunk = [UInt8]()
        chunk.reserveCapacity(16_384)
        for try await byte in bytes {
            chunk.append(byte)
            if chunk.count == 16_384 {
                data.append(contentsOf: chunk)
                chunk.removeAll(keepingCapacity: true)
                if data.count > Self.maxBytes { throw BreachCheckError.failed }
            }
        }
        data.append(contentsOf: chunk)
        if data.count > Self.maxBytes { throw BreachCheckError.failed }
        return data
    }
}

public struct BreachScanResult: Sendable, Equatable {
    /// Login id → times seen in breaches, for every login that was checked.
    public var counts: [String: Int] = [:]
    /// Logins whose check failed (no result available).
    public var failed: Set<String> = []
    public var cancelled = false

    public var breached: Set<String> { Set(counts.filter { $0.value > 0 }.keys) }
}

/// Explicit HIBP Pwned Passwords range check (k-anonymity: only a 5-character
/// SHA-1 prefix leaves the device). Results are kept by the caller in memory only.
public actor BreachChecker {
    public static let maxBytes = 200_000
    private let transport: any BreachTransport
    private let appVersion: String
    private let strictOffline: @Sendable () -> Bool
    private let enabled: @Sendable () -> Bool
    private let pause: Duration

    public init(transport: any BreachTransport, appVersion: String,
                strictOffline: @escaping @Sendable () -> Bool, enabled: @escaping @Sendable () -> Bool,
                pause: Duration = .seconds(1.5)) {
        self.transport = transport
        self.appVersion = appVersion
        self.strictOffline = strictOffline
        self.enabled = enabled
        self.pause = pause
    }

    private func gate() throws {
        if strictOffline() { throw BreachCheckError.strictOffline }
        if !enabled() { throw BreachCheckError.disabled }
    }

    /// Times the password appears in breaches; 0 = not found.
    public func check(_ password: String) async throws -> Int {
        try gate()
        // SHA-1 is mandated by the HIBP range API, not used for security.
        let digest = Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
        let prefix = String(digest.prefix(5)), suffix = String(digest.dropFirst(5))
        guard let url = URL(string: "https://api.pwnedpasswords.com/range/" + prefix) else {
            throw BreachCheckError.failed
        }
        let data: Data
        do {
            data = try await transport.get(url, headers: ["Add-Padding": "true",
                                                          "User-Agent": "LocalGateKeys/\(appVersion)"])
        } catch {
            throw BreachCheckError.failed
        }
        return try Self.count(in: data, suffix: suffix)
    }

    static func count(in data: Data, suffix: String) throws -> Int {
        guard data.count <= maxBytes, let text = String(data: data, encoding: .ascii) else {
            throw BreachCheckError.failed
        }
        var count = 0, valid = 0
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let parts = line.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2, parts[0].count == 35,
                  parts[0].allSatisfy(\.isHexDigit), !parts[1].isEmpty,
                  parts[1].allSatisfy({ $0.isASCII && $0.isNumber }) else { continue }
            valid += 1
            if parts[0].uppercased() == suffix { count = max(count, Int(parts[1]) ?? Int.max) }
        }
        guard valid > 0 else { throw BreachCheckError.failed }
        return count
    }

    /// Checks every login, requesting identical passwords once, pausing between requests.
    /// Stops early (cancelled = true) if the task is cancelled or checks become refused.
    public func scan(_ logins: [HealthLogin],
                     progress: @Sendable (Int, Int) -> Void) async -> BreachScanResult {
        var result = BreachScanResult()
        var groups: [String: [String]] = [:]
        var order: [String] = []
        for login in logins where !login.password.isEmpty {
            if groups[login.password] == nil { order.append(login.password) }
            groups[login.password, default: []].append(login.id)
        }
        let total = order.count
        progress(0, total)
        for (index, password) in order.enumerated() {
            if Task.isCancelled { result.cancelled = true; break }
            if index > 0 {
                do { try await Task.sleep(for: pause) } catch { result.cancelled = true; break }
            }
            let ids = groups[password] ?? []
            let outcome: Result<Int, Error>
            do { outcome = .success(try await check(password)) } catch { outcome = .failure(error) }
            // Cancelled mid-request: leave these logins "not checked", not failed.
            if Task.isCancelled { result.cancelled = true; break }
            switch outcome {
            case .success(let count):
                for id in ids { result.counts[id] = count }
            case .failure(BreachCheckError.strictOffline), .failure(BreachCheckError.disabled):
                result.cancelled = true
            case .failure:
                result.failed.formUnion(ids)
            }
            if result.cancelled { break }
            progress(index + 1, total)
        }
        return result
    }
}
