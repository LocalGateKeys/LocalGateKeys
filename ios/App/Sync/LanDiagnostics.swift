import Foundation
import Network
import AppShared

// Why a LAN connection failed, and on which Wi-Fi subnet this phone is. Pure logic here; the sockets that
// use it are in NWLanConnection.swift. Main app only (no UIKit: the e2e harness compiles this on macOS).

/// What went wrong with one LAN connection, in the terms the Sync screen explains to the user.
enum LanFailure: Equatable, Sendable {
    /// Nothing listens at that address and port (TCP RST).
    case refused
    /// No route to that address (wrong subnet, PC off this Wi-Fi).
    case unreachable
    /// No answer before the deadline (firewall dropping, or a host that is not there).
    case timedOut
    /// iOS Local Network privacy refused the connection.
    case localNetworkDenied
    /// The other side closed the connection after it was set up.
    case closedByPeer
    /// The user (or the run) cancelled.
    case cancelled
    case other

    enum Verdict: Equatable, Sendable {
        case fail(LanFailure)
        /// Keep waiting until the deadline; `denied`: Local Network privacy is (so far) refusing, which is
        /// also what a connection sees while iOS is still showing the permission prompt.
        case wait(denied: Bool)
    }

    /// kDNSServiceErr_PolicyDenied.
    static let policyDenied: Int32 = -65570

    /// A connection in `.waiting`: fail now when waiting cannot help, else keep waiting.
    static func verdict(waiting error: NWError?, unsatisfied: NWPath.UnsatisfiedReason?) -> Verdict {
        if unsatisfied == .localNetworkDenied { return .wait(denied: true) }
        guard let error else { return .wait(denied: false) }
        // No usable network yet (Wi-Fi still joining): waiting can help.
        if case .posix(.ENETDOWN) = error { return .wait(denied: false) }
        switch classify(error) {
        case .localNetworkDenied: return .wait(denied: true)
        case .refused: return .fail(.refused)
        case .unreachable: return .fail(.unreachable)
        case .timedOut: return .fail(.timedOut)
        default: return .wait(denied: false)
        }
    }

    static func classify(_ error: NWError) -> LanFailure {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNREFUSED: return .refused
            case .EHOSTUNREACH, .ENETUNREACH, .EHOSTDOWN, .ENETDOWN, .EADDRNOTAVAIL: return .unreachable
            case .ETIMEDOUT: return .timedOut
            case .ECONNRESET, .EPIPE, .ECONNABORTED, .ENOTCONN: return .closedByPeer
            case .ECANCELED: return .cancelled
            default: return .other
            }
        case .dns(let code): return code == policyDenied ? .localNetworkDenied : .other
        default: return .other
        }
    }
}

/// What a connect that runs into its deadline failed with: the latest state decides. A denied wait (the
/// Local Network prompt showing) followed by `.preparing` (the user tapped Allow) and then silence (a
/// firewall dropping the SYN) is a timeout, not a denial.
struct ConnectWait: Equatable, Sendable {
    private(set) var denied = false

    mutating func observe(_ state: NWConnection.State, unsatisfied: NWPath.UnsatisfiedReason?) {
        switch state {
        case .waiting(let e):
            if case .wait(let d) = LanFailure.verdict(waiting: e, unsatisfied: unsatisfied) { denied = d } else { denied = false }
        case .preparing, .ready: denied = false
        default: break
        }
    }

    var deadlineFailure: LanFailure { denied ? .localNetworkDenied : .timedOut }
}

/// An IPv4 network: address and contiguous netmask, as `getifaddrs` reports for the Wi-Fi interface.
struct IPv4Subnet: Equatable, Sendable, CustomStringConvertible {
    let network: UInt32
    let prefixLength: Int
    var mask: UInt32 { prefixLength == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefixLength) }

    init?(address: String, netmask: String) {
        guard let a = Self.parse(address), let m = Self.parse(netmask) else { return nil }
        let ones = m.nonzeroBitCount
        guard m == (ones == 0 ? 0 : ~UInt32(0) << UInt32(32 - ones)) else { return nil }
        prefixLength = ones
        network = a & m
    }

    /// True or false for an IPv4 host; nil when the host is not IPv4 text (no verdict).
    func contains(_ host: String) -> Bool? {
        guard let h = Self.parse(host) else { return nil }
        return h & mask == network
    }

    var description: String { "\(Self.format(network))/\(prefixLength)" }

    /// The subnet when `host` is IPv4 and outside it (the case worth explaining after a failure), else nil.
    static func mismatch(host: String, subnet: IPv4Subnet?) -> IPv4Subnet? {
        guard let subnet, subnet.contains(host) == false else { return nil }
        return subnet
    }

    static func parse(_ text: String) -> UInt32? {
        guard case .v4(let b)? = LanAddress.parse(text) else { return nil }
        return b.reduce(0) { $0 << 8 | UInt32($1) }
    }

    static func format(_ v: UInt32) -> String {
        [24, 16, 8, 0].map { String((v >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }
}

/// One IPv4 address of a network interface.
struct IPv4Interface: Equatable, Sendable {
    let name: String
    let address: String
    let netmask: String
    let isUp: Bool
    let isLoopback: Bool

    /// The Wi-Fi subnet: en0 when it is up with IPv4, else the first other up `en*` (Wi-Fi/Ethernet)
    /// IPv4 interface. Never cellular (`pdp_ip*`), VPN tunnels (`utun*`) or bridges: nil then.
    static func wifiSubnet(from interfaces: [IPv4Interface]) -> IPv4Subnet? {
        let usable = interfaces.filter { $0.isUp && !$0.isLoopback && $0.name.hasPrefix("en") }
        let pick = usable.first { $0.name == "en0" } ?? usable.first
        return pick.flatMap { IPv4Subnet(address: $0.address, netmask: $0.netmask) }
    }

    /// The phone's current Wi-Fi subnet, or nil (no Wi-Fi, or IPv6 only).
    static func currentWiFiSubnet() -> IPv4Subnet? { wifiSubnet(from: current()) }

    static func current() -> [IPv4Interface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [IPv4Interface] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let i = p.pointee
            guard let a = i.ifa_addr, a.pointee.sa_family == sa_family_t(AF_INET), let m = i.ifa_netmask,
                  let address = text(a), let netmask = text(m) else { continue }
            let flags = Int32(i.ifa_flags)
            out.append(IPv4Interface(name: String(cString: i.ifa_name), address: address, netmask: netmask,
                                     isUp: flags & IFF_UP != 0 && flags & IFF_RUNNING != 0,
                                     isLoopback: flags & IFF_LOOPBACK != 0))
        }
        return out
    }

    private static func text(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let ok = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
            var addr = sin.pointee.sin_addr
            return inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count)) != nil
        }
        return ok ? String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self) : nil
    }
}
