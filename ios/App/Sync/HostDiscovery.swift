import Foundation
import Network
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

// Finding the paired host by Bonjour / mDNS when its pinned address does not answer (plan
// 2026-10-29-sync-ip-change, section 3; Android `HostDiscovery.kt`). The browse only says where to dial; the
// session hello still checks the pinned keys.

/// Browses one DNS-SD service type and returns the resolved announcements (host address text, port, TXT).
/// `wanted` sees each TXT record before it is resolved, so only announcements that can match are resolved.
/// Production: `NWServiceBrowser`; tests: a fake. Throws `LanSocketError` `.cancelled` when the task is cancelled.
protocol ServiceBrowsing: Sendable {
    func browse(serviceType: String, seconds: TimeInterval,
                wanted: @escaping @Sendable ([String: String]) -> Bool) async throws -> [Discovery.Announcement]
}

/// `ServiceBrowsing` over `NWBrowser` (`.bonjourWithTXTRecord`, declared in `NSBonjourServices`), never over
/// cellular. Services found during the window are resolved newest first, one after another, each within
/// `resolveSeconds`, at most `maxResolves` within `resolveBudgetSeconds` (Android `NsdServiceBrowser`). A
/// resolve opens a TCP connection to the service and reads the remote IPv4 address and port once it is
/// ready; nothing is sent and the connection is cancelled at once.
struct NWServiceBrowser: ServiceBrowsing {
    static let resolveSeconds: TimeInterval = 1
    static let maxResolves = 16
    static let resolveBudgetSeconds: TimeInterval = 6

    private final class Found: @unchecked Sendable {
        let lock = NSLock()
        var order: [String] = []
        var results: [String: (NWEndpoint, [String: String])] = [:]
    }

    func browse(serviceType: String, seconds: TimeInterval,
                wanted: @escaping @Sendable ([String: String]) -> Bool) async throws -> [Discovery.Announcement] {
        let params = NWParameters()
        params.prohibitedInterfaceTypes = [.cellular]
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: serviceType, domain: nil), using: params)
        let found = Found()
        browser.stateUpdateHandler = { _ in }
        browser.browseResultsChangedHandler = { results, _ in
            found.lock.withLock {
                for r in results {
                    guard case .service(let name, _, _, _) = r.endpoint else { continue }
                    var txt: [String: String] = [:]
                    if case .bonjour(let record) = r.metadata { txt = record.dictionary }
                    guard wanted(txt) else { continue }
                    if found.results[name] == nil {
                        guard found.order.count < Self.maxResolves else { continue }
                        found.order.append(name)
                    }
                    found.results[name] = (r.endpoint, txt)
                }
            }
        }
        browser.start(queue: DispatchQueue(label: "lgk.lan.browse"))
        defer { browser.cancel() }
        do { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) } catch {
            throw LanSocketError("cancelled", kind: .cancelled)
        }
        browser.cancel()
        // Newest first: a flood of junk announced before the real host can't push it out of the resolve budget.
        let services: [(NWEndpoint, [String: String])] = found.lock.withLock {
            found.order.reversed().compactMap { found.results[$0] }
        }
        let deadline = Date().addingTimeInterval(Self.resolveBudgetSeconds)
        var out: [Discovery.Announcement] = []
        for (endpoint, txt) in services {
            if Task.isCancelled { throw LanSocketError("cancelled", kind: .cancelled) }
            if Date() >= deadline { break }
            if let (host, port) = await Self.resolve(endpoint) {
                out.append(Discovery.Announcement(host: host, port: port, txt: txt))
            }
        }
        return out
    }

    /// The IPv4 address and port behind a service endpoint, or nil within `resolveSeconds`.
    static func resolve(_ endpoint: NWEndpoint) async -> (String, Int)? {
        let params = NWParameters.tcp
        params.prohibitedInterfaceTypes = [.cellular]
        if let ip = params.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options { ip.version = .v4 }
        let conn = NWConnection(to: endpoint, using: params)
        let queue = DispatchQueue(label: "lgk.lan.resolve")
        return await withCheckedContinuation { (cont: CheckedContinuation<(String, Int)?, Never>) in
            let once = ResolveOnce()
            @Sendable func finish(_ value: (String, Int)?) { once.run { conn.cancel(); cont.resume(returning: value) } }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if case .hostPort(let host, let port)? = conn.currentPath?.remoteEndpoint, case .ipv4(let a) = host {
                        let text = "\(a)".split(separator: "%").first.map(String.init) ?? "\(a)"
                        finish((text, Int(port.rawValue)))
                    } else {
                        finish(nil)
                    }
                case .failed, .cancelled, .waiting: finish(nil)
                default: break
                }
            }
            conn.start(queue: queue)
            queue.asyncAfter(deadline: .now() + resolveSeconds) { finish(nil) }
        }
    }
}

private final class ResolveOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func run(_ body: () -> Void) { if lock.withLock({ defer { done = true }; return !done }) { body() } }
}

/// The pinned dial, then discovery when the pinned address does not answer (Android
/// `SocketLanTransport.exchangeViewsFindingHost`). `attempt` is one full `LanClient.sync` (the normal handshake
/// against the pinned keys) with the given peer.
enum HostFinder {
    /// Plan: browse for up to 3 s when the pinned address fails.
    static let browseSeconds: TimeInterval = 3

    struct Result: Sendable {
        let states: [ItemState]
        /// The address the paired host answered at with its pinned keys, when it is not the pinned one.
        let moved: LanEndpoint?
        /// The host's view header (its rollback witness when it is format 2); nil when unknown.
        var header: ViewHeader? = nil
    }

    static func exchange(peer: PinnedPeer, groupKey: GroupKey, now: Int64, browser: (any ServiceBrowsing)?,
                         browseSeconds: TimeInterval = browseSeconds,
                         attempt: (PinnedPeer) async throws -> [ItemState]) async throws -> Result {
        try await exchangeWithHeader(peer: peer, groupKey: groupKey, now: now, browser: browser,
                                     browseSeconds: browseSeconds) { LanExchange(states: try await attempt($0)) }
    }

    /// `exchange`, keeping the host's view header (`LanClient.exchange`).
    static func exchangeWithHeader(peer: PinnedPeer, groupKey: GroupKey, now: Int64, browser: (any ServiceBrowsing)?,
                                   browseSeconds: TimeInterval = browseSeconds,
                                   attempt: (PinnedPeer) async throws -> LanExchange) async throws -> Result {
        do {
            let first = try await attempt(peer)
            return Result(states: first.states, moved: nil, header: first.header)
        } catch let e as LanPeerNotAnswering {
            guard let browser else { throw e }
            if Task.isCancelled { throw LanSocketError("cancelled", kind: .cancelled) }
            let accepted = Discovery.acceptedTags(groupKey, hostDeviceID: peer.deviceID, now: now)
            let found: [Discovery.Announcement]
            do {
                found = try await browser.browse(serviceType: Discovery.serviceType, seconds: browseSeconds,
                                                 wanted: { txt in txt["v"] == Discovery.txtVersion && txt["t"].map(accepted.contains) == true })
            } catch let x as LanSocketError where x.kind == .cancelled {
                throw x
            } catch {
                throw e
            }
            for candidate in Discovery.candidates(found, accepted: accepted, alreadyTried: peer.endpoint) {
                if Task.isCancelled { throw LanSocketError("cancelled", kind: .cancelled) }
                let moved = PinnedPeer(deviceID: peer.deviceID, groupID: peer.groupID, signingPublic: peer.signingPublic,
                                       exchangePublic: peer.exchangePublic, endpoint: candidate)
                do {
                    let answer = try await attempt(moved)
                    return Result(states: answer.states, moved: candidate, header: answer.header)
                } catch is LanPeerNotAnswering {
                    continue
                } catch is LanTransportError {
                    continue   // not the paired host: its hello failed the pinned keys
                } catch let x as LanSyncError {
                    // An unsigned version refusal proves nothing about who answered.
                    if x.reason == "peer-update-needed" || x.reason == "lan-update-needed" { continue }
                    throw x
                } catch let x as LanSocketError {
                    if x.kind == .cancelled || Task.isCancelled { throw x }
                    continue
                }
            }
            throw e
        }
    }
}
