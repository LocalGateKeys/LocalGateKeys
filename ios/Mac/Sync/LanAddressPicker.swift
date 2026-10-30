import Foundation
import Darwin
import LGKCore
import AppSharedMac

/// One IPv4 address of a network interface of this Mac.
struct LanInterfaceAddress: Equatable, Sendable, Identifiable {
    let interface: String
    let address: String
    var id: String { "\(interface) \(address)" }
    /// What the address picker shows, for example "192.168.1.20 (en0)".
    var label: String { "\(address) (\(interface))" }
}

/// The address Wi-Fi sync listens on (desktop `sync_view.validate_lan_endpoint` / `suggest_lan_endpoint` and
/// `wifi_suggest`): a private IPv4 address of an `en*` interface (Wi-Fi or Ethernet). VPN and tunnel
/// interfaces (`utun*`, `ipsec*`, `ppp*`, bridges) are never offered; loopback is refused. The user picks one
/// of the candidates (the first private one is suggested) and may change the port (default 47821).
enum LanAddressPicker {
    /// Desktop `DEFAULT_LAN_PORT`.
    static let defaultPort = 47821
    static let portRange = 1024...65535

    static let emptyText = String(localized: "Enter this Mac's address and port, for example 192.168.1.20:47821.")
    static let formatText = String(localized: "Use address:port, for example 192.168.1.20:47821.")
    static let bracketText = String(localized: "Put an IPv6 address in brackets, for example [fe80::1]:47821.")
    static let nameText = String(localized: "Use this Mac's numeric address (like 192.168.1.20), not a name.")
    static let privateText = String(localized: "Use this Mac's address on your home network (a private or link-local address).")
    static let portText = String(localized: "Use a port between 1024 and 65535.")

    /// True for an address this Mac may listen on: private or link-local (`LanAddress.isLAN`), never loopback
    /// or unspecified. `allowLoopback` exists for the loopback tests only (DEBUG builds).
    static func isHostable(_ host: String, allowLoopback: Bool = false) -> Bool {
        guard let parsed = LanAddress.parse(host), LanAddress.isLAN(host) else { return false }
        switch parsed {
        case .v4(let b):
            if b[0] == 127 { return allowLoopback }
            return true
        case .v6(let b):
            if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return allowLoopback }
            return true
        }
    }

    /// The listening candidates among `addresses`: IPv4 on `en*` interfaces, private first and link-local
    /// (169.254/16) last, each address once.
    static func candidates(_ addresses: [LanInterfaceAddress]) -> [LanInterfaceAddress] {
        var privateOnes: [LanInterfaceAddress] = [], linkLocal: [LanInterfaceAddress] = []
        var seen = Set<String>()
        for a in addresses where isWiFiOrEthernet(a.interface) {
            guard case .v4(let b)? = LanAddress.parse(a.address), isHostable(a.address), seen.insert(a.address).inserted else { continue }
            if b[0] == 169 && b[1] == 254 { linkLocal.append(a) } else { privateOnes.append(a) }
        }
        return privateOnes + linkLocal
    }

    /// `en0`, `en1`, … (Wi-Fi, Ethernet, Thunderbolt Ethernet). VPN (`utun`, `ipsec`, `ppp`), bridge, AWDL and
    /// loopback interfaces are not.
    static func isWiFiOrEthernet(_ name: String) -> Bool {
        guard name.hasPrefix("en"), name.count > 2 else { return false }
        return name.dropFirst(2).allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// The suggested endpoint: `current` when it is still one of the candidates (or there are none), else the
    /// first candidate with `current`'s port (or the default port).
    static func suggestion(current: LanEndpoint?, candidates: [LanInterfaceAddress]) -> LanEndpoint? {
        let port = current?.port ?? defaultPort
        if let current, candidates.isEmpty || candidates.contains(where: { $0.address == current.host }) { return current }
        guard let first = candidates.first else { return nil }
        return try? LanEndpoint(validating: first.address, port: port)
    }

    /// The endpoint to listen on after this Mac's address changed (desktop `lan_interfaces.followed_endpoint`), or
    /// nil to keep `stored`: only when `stored`'s host is on no interface any more and exactly one obvious
    /// candidate exists (the only one, or the only private one beside link-local addresses); the port is kept.
    /// No candidates at all (nothing could be read, or no network) never moves.
    static func followed(stored: LanEndpoint, candidates: [LanInterfaceAddress]) -> LanEndpoint? {
        guard !candidates.isEmpty, !candidates.contains(where: { $0.address == stored.host }) else { return nil }
        let pick: LanInterfaceAddress?
        if candidates.count == 1 {
            pick = candidates[0]
        } else {
            let preferred = candidates.filter { !$0.address.hasPrefix("169.254.") }
            pick = preferred.count == 1 ? preferred[0] : nil
        }
        guard let pick else { return nil }
        return try? LanEndpoint(validating: pick.address, port: stored.port)
    }

    /// `validate_lan_endpoint`: "host:port" (IPv6 in brackets) -> the endpoint, or the Windows message.
    static func validate(_ text: String, allowLoopback: Bool = false) -> Result<LanEndpoint, LanAddressError> {
        let raw = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return .failure(LanAddressError(emptyText)) }
        guard let colon = raw.lastIndex(of: ":") else { return .failure(LanAddressError(formatText)) }
        var host = String(raw[..<colon])
        let portString = String(raw[raw.index(after: colon)...])
        guard !host.isEmpty else { return .failure(LanAddressError(formatText)) }
        let bracketed = host.hasPrefix("[") && host.hasSuffix("]") && host.count >= 2
        if bracketed { host = String(host.dropFirst().dropLast()) } else if host.contains(":") {
            return .failure(LanAddressError(bracketText))
        }
        guard let parsed = LanAddress.parse(host) else { return .failure(LanAddressError(nameText)) }
        let isV6: Bool
        if case .v6 = parsed { isV6 = true } else { isV6 = false }
        guard bracketed == isV6 else { return .failure(LanAddressError(formatText)) }
        guard isHostable(host, allowLoopback: allowLoopback), !isUnspecified(parsed) else { return .failure(LanAddressError(privateText)) }
        guard !portString.isEmpty, portString.allSatisfy({ $0.isASCII && $0.isNumber }), portString.count <= 5,
              let port = Int(portString), portRange.contains(port) else { return .failure(LanAddressError(portText)) }
        guard let endpoint = try? LanEndpoint(validating: host, port: port) else { return .failure(LanAddressError(privateText)) }
        return .success(endpoint)
    }

    private static func isUnspecified(_ p: LanAddress.Parsed) -> Bool {
        switch p { case .v4(let b), .v6(let b): return b.allSatisfy { $0 == 0 } }
    }

    /// This Mac's IPv4 interface addresses (`getifaddrs`; nothing is sent).
    static func interfaceAddresses() -> [LanInterfaceAddress] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [LanInterfaceAddress] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, let sa = entry.pointee.ifa_addr,
                  sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
            out.append(LanInterfaceAddress(interface: String(cString: entry.pointee.ifa_name),
                                           address: String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)))
        }
        return out
    }

    /// The candidates of this Mac right now.
    static func currentCandidates() -> [LanInterfaceAddress] { candidates(interfaceAddresses()) }

    /// "host:port" as typed back into the field (IPv6 in brackets).
    static func text(_ e: LanEndpoint) -> String { SyncWording.hostPort(e) }
}

struct LanAddressError: Error, Equatable {
    let message: String
    init(_ message: String) { self.message = message }
}
