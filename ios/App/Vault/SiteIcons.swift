import SwiftUI
import ImageIO
import UniformTypeIdentifiers
import CryptoKit
import Darwin
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

#if os(macOS)
import AppKit
typealias PlatformImage = NSImage
#else
import UIKit
typealias PlatformImage = UIImage
#endif

/// Website icons for the vault (desktop `item_icons` limits). Off by default (Settings › Show website icons):
/// each download asks only `https://<host>/…` for the site's icon and sends nothing else, but it tells that
/// site, and the network, that this phone has an account there. So: public HTTPS hosts only, at most two
/// downloads at a time, 5 s and 256 KB each, decoded within fixed limits and re-encoded as a small PNG.
/// Icons are cached on disk (one download per site per month; a failure is retried after a day) and are
/// only requested by vault screens, which exist only while the app is unlocked.
@MainActor
@Observable
final class SiteIconStore {
    static let shared = SiteIconStore()

    nonisolated static let maxDownloadBytes = 256 * 1024
    nonisolated static let maxSourcePixels = 1024
    nonisolated static let pixelSize = 96
    nonisolated static let maxInFlight = 2
    nonisolated static let freshFor: TimeInterval = 30 * 86_400
    nonisolated static let retryFailureAfter: TimeInterval = 86_400

    private(set) var images: [String: PlatformImage] = [:]
    @ObservationIgnored private var failed: [String: Date] = [:]
    @ObservationIgnored private var inFlight: Set<String> = []
    @ObservationIgnored private var queue: [String] = []
    @ObservationIgnored let directory: URL?
    @ObservationIgnored let settings: AppSettings
    @ObservationIgnored let fetch: @Sendable (URL) async throws -> Data
    @ObservationIgnored let now: () -> Date

    init(directory: URL? = SiteIconStore.defaultDirectory, settings: AppSettings = .shared,
         fetch: @escaping @Sendable (URL) async throws -> Data = SiteIconFetcher.fetch, now: @escaping () -> Date = Date.init) {
        self.directory = directory; self.settings = settings; self.fetch = fetch; self.now = now
    }

    static var defaultDirectory: URL? {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first?
            .appendingPathComponent("SiteIcons", isDirectory: true)
    }

    /// The icon for a host, if it is loaded. Safe to call while a view draws (changes nothing).
    func image(for host: String) -> PlatformImage? {
        guard settings.showWebsiteIcons, let host = Self.eligibleHost(host) else { return nil }
        return images[host]
    }

    /// Loads a host's icon: from the disk cache, else (queued) from the site. Call from a view's task.
    func request(_ host: String) {
        guard settings.showWebsiteIcons, let host = Self.eligibleHost(host), images[host] == nil else { return }
        if let at = failed[host], now().timeIntervalSince(at) < Self.retryFailureAfter { return }
        if inFlight.contains(host) || queue.contains(host) { return }
        if let cached = loadCached(host) { images[host] = cached; return }
        queue.append(host)
        pump()
    }

    /// Lets tests wait for the downloads in progress.
    var isIdle: Bool { inFlight.isEmpty && queue.isEmpty }

    /// Settings turned icons off, or the vault was erased.
    func clear() {
        images.removeAll(); failed.removeAll(); queue.removeAll()
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }

    private func pump() {
        while inFlight.count < Self.maxInFlight, !queue.isEmpty {
            let host = queue.removeFirst()
            inFlight.insert(host)
            Task { await load(host) }
        }
    }

    private func load(_ host: String) async {
        defer { inFlight.remove(host); pump() }
        for path in ["/apple-touch-icon.png", "/favicon.ico"] {
            guard let url = URL(string: "https://\(host)\(path)") else { continue }
            guard let data = try? await fetch(url), let png = Self.normalized(data) else { continue }
            guard settings.showWebsiteIcons, let image = PlatformImage(data: png) else { return }
            save(png, for: host)
            images[host] = image
            return
        }
        failed[host] = now()
    }

    // MARK: disk

    private func file(_ host: String) -> URL? {
        let name = SHA256.hash(data: Data(host.utf8)).map { String(format: "%02x", $0) }.joined()
        return directory?.appendingPathComponent(name + ".png")
    }

    private func loadCached(_ host: String) -> PlatformImage? {
        guard let url = file(host),
              let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let modified = attrs[.modificationDate] as? Date,
              now().timeIntervalSince(modified) < Self.freshFor,
              let data = try? Data(contentsOf: url) else { return nil }
        // Icons cached by an earlier build were written with the weaker class: raise it (see `save`).
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        return PlatformImage(data: data)
    }

    /// `complete` protection (audit 2026-10-24 L-8): the list of sites with an account here is unreadable while
    /// the phone is locked. Icons are only read and written by vault screens, in the foreground and unlocked.
    private func save(_ png: Data, for host: String) {
        guard let directory, let url = file(host) else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? png.write(to: url, options: [.atomic, .completeFileProtection])
    }

    // MARK: limits

    /// A lower-case DNS name with a dot, not an IP literal, not `localhost` or a local-network name.
    nonisolated static func eligibleHost(_ raw: String) -> String? {
        var host = raw.lowercased()
        while host.hasSuffix(".") { host.removeLast() }
        guard (3...253).contains(host.utf8.count), host.contains("."),
              host.unicodeScalars.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" || $0 == "." })
        else { return nil }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-") }) else { return nil }
        if labels.allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil }          // 192.168.1.1
        if let tld = labels.last, tld.allSatisfy(\.isNumber) { return nil }
        for suffix in ["localhost", "local", "lan", "home", "internal", "intranet", "corp", "home.arpa", "localdomain", "test",
                       "invalid", "example"] where host == suffix || host.hasSuffix("." + suffix) {
            return nil
        }
        return host
    }

    /// The bytes as a small PNG, or nil when they are not an image within the limits.
    nonisolated static func normalized(_ data: Data) -> Data? {
        guard !data.isEmpty, data.count <= maxDownloadBytes,
              let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              CGImageSourceGetCount(source) >= 1 else { return nil }
        // Pick the largest frame within the limits (an .ico holds several sizes).
        var best: (index: Int, size: Int)?
        for i in 0..<min(CGImageSourceGetCount(source), 16) {
            guard let p = CGImageSourceCopyPropertiesAtIndex(source, i, nil) as? [CFString: Any],
                  let w = p[kCGImagePropertyPixelWidth] as? Int, let h = p[kCGImagePropertyPixelHeight] as? Int,
                  (1...maxSourcePixels).contains(w), (1...maxSourcePixels).contains(h) else { continue }
            if best == nil || w * h > best!.size { best = (i, w * h) }
        }
        guard let best,
              let thumb = CGImageSourceCreateThumbnailAtIndex(source, best.index, [
                  kCGImageSourceCreateThumbnailFromImageAlways: true,
                  kCGImageSourceThumbnailMaxPixelSize: pixelSize,
                  kCGImageSourceCreateThumbnailWithTransform: true,
                  kCGImageSourceShouldCacheImmediately: true,
              ] as CFDictionary),
              thumb.width >= 16, thumb.height >= 16 else { return nil }   // 1×1 tracking pixels, tiny defaults
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, thumb, nil)
        return CGImageDestinationFinalize(dest) ? out as Data : nil
    }
}

/// One icon download: HTTPS only, no cookies or credentials, no cache, 5 s, at most 256 KB, and a redirect
/// is followed only to another HTTPS URL on an eligible host. Every host (first and redirected) must resolve
/// to public addresses only (`SiteIconAddress`): a public name pointing at the LAN, loopback or link-local is
/// refused before any request (audit 2026-10-24 L-8). URLSession resolves again when it connects, so a DNS
/// answer that changes in between (rebinding) is not covered; the request carries no cookie or credential.
enum SiteIconFetcher {
    final class Delegate: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? {
            guard let url = request.url, url.scheme == "https", let host = url.host(),
                  let eligible = SiteIconStore.eligibleHost(host), SiteIconAddress.resolvesToPublicOnly(eligible) else { return nil }
            return request
        }
    }

    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = nil; c.httpShouldSetCookies = false; c.urlCredentialStorage = nil; c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.timeoutIntervalForRequest = 5; c.timeoutIntervalForResource = 5
        c.httpMaximumConnectionsPerHost = 1
        c.httpAdditionalHeaders = ["Accept": "image/*"]
        return URLSession(configuration: c, delegate: Delegate(), delegateQueue: nil)
    }()

    struct Refused: Error {}

    @Sendable static func fetch(_ url: URL) async throws -> Data {
        guard url.scheme == "https", let host = url.host(), SiteIconAddress.resolvesToPublicOnly(host) else { throw Refused() }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw Refused() }
        if http.expectedContentLength > Int64(SiteIconStore.maxDownloadBytes) { throw Refused() }
        var data = Data()
        for try await byte in bytes {
            data.append(byte)
            if data.count > SiteIconStore.maxDownloadBytes { throw Refused() }
        }
        return data
    }
}

/// Whether an icon host's DNS answers are all public unicast addresses. Refused: no answer, and any address
/// that is unspecified, loopback, private (RFC 1918, unique local), carrier-grade NAT, link-local, multicast,
/// benchmarking or reserved, including those embedded in IPv4-mapped and NAT64 IPv6 addresses.
enum SiteIconAddress {
    /// Blocking `getaddrinfo` (called from the download task, never the main actor).
    static func resolvesToPublicOnly(_ host: String) -> Bool {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var list: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "443", &hints, &list) == 0, let first = list else { return false }
        defer { freeaddrinfo(first) }
        var any = false
        var node: UnsafeMutablePointer<addrinfo>? = first
        while let ai = node {
            defer { node = ai.pointee.ai_next }
            guard let sa = ai.pointee.ai_addr else { continue }
            switch Int32(sa.pointee.sa_family) {
            case AF_INET:
                let v4 = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                let bytes = withUnsafeBytes(of: v4) { Array($0) }   // s_addr is in network order: bytes as on the wire
                guard isPublic(ipv4: bytes) else { return false }
                any = true
            case AF_INET6:
                let v6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                let bytes = withUnsafeBytes(of: v6) { Array($0) }
                guard isPublic(ipv6: bytes) else { return false }
                any = true
            default:
                return false
            }
        }
        return any
    }

    /// Four bytes, network order.
    static func isPublic(ipv4 b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        switch (b[0], b[1]) {
        case (0, _), (10, _), (127, _): return false                       // this network, private, loopback
        case (100, 64...127): return false                                 // carrier-grade NAT
        case (169, 254): return false                                      // link-local
        case (172, 16...31): return false                                  // private
        case (192, 168): return false                                      // private
        case (198, 18...19): return false                                  // benchmarking
        default: break
        }
        if b[0] == 192, b[1] == 0, b[2] == 0 { return false }               // IETF protocol assignments
        if b[0] >= 224 { return false }                                    // multicast, reserved, broadcast
        return true
    }

    /// Sixteen bytes, network order.
    static func isPublic(ipv6 b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        if b[0..<15].allSatisfy({ $0 == 0 }) { return false }              // :: and ::1
        if b[0] == 0xfe, b[1] & 0xc0 == 0x80 { return false }              // fe80::/10 link-local
        if b[0] & 0xfe == 0xfc { return false }                            // fc00::/7 unique local
        if b[0] == 0xff { return false }                                   // multicast
        if b[0..<10].allSatisfy({ $0 == 0 }), b[10] == 0xff, b[11] == 0xff { // ::ffff:a.b.c.d
            return isPublic(ipv4: Array(b[12..<16]))
        }
        if Array(b[0..<12]) == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] { // 64:ff9b::/96 NAT64
            return isPublic(ipv4: Array(b[12..<16]))
        }
        return true
    }
}

/// The square at the start of a row: the site's icon when there is one, else the kind's symbol.
#if os(iOS)
struct ItemAvatar: View {
    let item: VaultItem
    var size: CGFloat = 42
    var store: SiteIconStore = .shared

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.29, style: .continuous)
        Group {
            if let host = item.iconHost, let image = store.image(for: host) {
                Image(uiImage: image).resizable().interpolation(.high).scaledToFit()
                    .padding(size * 0.14)
                    .background(Color.white, in: shape)
            } else if let logo = item.siteLogo {
                // Not downloaded (switch off, offline, no icon yet): the bundled logo (SiteLogos.swift).
                Image(logo.imageName).renderingMode(.template).resizable().scaledToFit()
                    .foregroundStyle(logo.isLight ? Color.black : Color.white)
                    .padding(size * 0.24)
                    .frame(width: size, height: size)
                    .background(logo.color, in: shape)
            } else {
                Image(systemName: VaultRow.icon(item.kind))
                    .font(.system(size: size * 0.43, weight: .medium))
                    .foregroundStyle(VaultRow.tint(item.kind))
                    .frame(width: size, height: size)
                    .background(VaultRow.tint(item.kind).opacity(0.14), in: shape)
            }
        }
        .frame(width: size, height: size)
        .clipShape(shape)
        .accessibilityHidden(true)
        .task(id: item.iconHost) { if let host = item.iconHost { store.request(host) } }
    }
}
#endif

extension VaultItem {
    /// The host whose icon a row shows: web logins, bookmarks and passkeys.
    var iconHost: String? {
        let host: String?
        switch kind {
        case "web": host = (record["scope"]?.objectValue?["origin"]?.stringValue).flatMap { URLComponents(string: $0)?.host }
        case "bookmark": host = (record["payload"]?.objectValue?["url"]?.stringValue).flatMap { URLComponents(string: $0)?.host }
        case "passkey": host = record["payload"]?.objectValue?["relying_party_id"]?.stringValue
        default: host = nil
        }
        return host.flatMap { $0.isEmpty ? nil : $0.lowercased() }
    }
}
