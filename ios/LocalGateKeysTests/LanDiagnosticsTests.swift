import XCTest
import Network
import AppShared
@testable import LocalGateKeys

final class LanDiagnosticsTests: XCTestCase {
    // MARK: waiting-state classification

    func test_refused_and_unroutable_fail_at_once() {
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.ECONNREFUSED), unsatisfied: nil), .fail(.refused))
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.EHOSTUNREACH), unsatisfied: nil), .fail(.unreachable))
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.ENETUNREACH), unsatisfied: nil), .fail(.unreachable))
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.ETIMEDOUT), unsatisfied: nil), .fail(.timedOut))
    }

    func test_policy_denied_keeps_waiting_for_the_prompt() {
        // kDNSServiceErr_PolicyDenied: also what a connection sees while the Local Network prompt is showing.
        XCTAssertEqual(LanFailure.verdict(waiting: .dns(-65570), unsatisfied: nil), .wait(denied: true))
        // The path's own reason wins over the socket error (iOS may report EHOSTUNREACH while denied).
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.EHOSTUNREACH), unsatisfied: .localNetworkDenied), .wait(denied: true))
        // Network down (Wi-Fi still joining): waiting can help.
        XCTAssertEqual(LanFailure.verdict(waiting: .posix(.ENETDOWN), unsatisfied: .notAvailable), .wait(denied: false))
    }

    func test_deadline_verdict_follows_the_latest_state() {
        // Prompt shown (denied wait), user taps Allow (preparing), then a firewall drops the SYN.
        var w = ConnectWait()
        w.observe(.waiting(.dns(-65570)), unsatisfied: nil)
        XCTAssertEqual(w.deadlineFailure, .localNetworkDenied)
        w.observe(.preparing, unsatisfied: nil)
        XCTAssertEqual(w.deadlineFailure, .timedOut)
        // Each waiting verdict sets it afresh.
        w.observe(.waiting(.dns(-65570)), unsatisfied: nil)
        w.observe(.waiting(.posix(.ENETDOWN)), unsatisfied: nil)
        XCTAssertEqual(w.deadlineFailure, .timedOut)
        w.observe(.waiting(.posix(.EHOSTUNREACH)), unsatisfied: .localNetworkDenied)
        XCTAssertEqual(w.deadlineFailure, .localNetworkDenied)
        XCTAssertEqual(ConnectWait().deadlineFailure, .timedOut)
    }

    func test_failed_state_classification() {
        XCTAssertEqual(LanFailure.classify(.posix(.ECONNREFUSED)), .refused)
        XCTAssertEqual(LanFailure.classify(.posix(.ECONNRESET)), .closedByPeer)
        XCTAssertEqual(LanFailure.classify(.posix(.EPIPE)), .closedByPeer)
        XCTAssertEqual(LanFailure.classify(.posix(.ECANCELED)), .cancelled)
        XCTAssertEqual(LanFailure.classify(.dns(-65570)), .localNetworkDenied)
        XCTAssertEqual(LanFailure.classify(.posix(.EACCES)), .other)
    }

    // MARK: subnet

    func test_subnet_contains_and_describes() throws {
        let s = try XCTUnwrap(IPv4Subnet(address: "192.168.1.37", netmask: "255.255.255.0"))
        XCTAssertEqual(s.description, "192.168.1.0/24")
        XCTAssertEqual(s.contains("192.168.1.5"), true)
        XCTAssertEqual(s.contains("192.168.60.11"), false)
        XCTAssertEqual(s.contains("10.0.0.1"), false)
        XCTAssertNil(s.contains("fe80::1"))       // not IPv4: no verdict
        XCTAssertNil(s.contains("not an address"))
        let wide = try XCTUnwrap(IPv4Subnet(address: "10.20.30.40", netmask: "255.255.240.0"))
        XCTAssertEqual(wide.description, "10.20.16.0/20")
        XCTAssertEqual(wide.contains("10.20.31.1"), true)
        XCTAssertEqual(wide.contains("10.20.32.1"), false)
        XCTAssertNil(IPv4Subnet(address: "192.168.1.1", netmask: "255.0.255.0"))   // not a contiguous mask
    }

    func test_wifi_interface_choice() {
        func i(_ n: String, _ a: String, up: Bool = true, loop: Bool = false) -> IPv4Interface {
            IPv4Interface(name: n, address: a, netmask: "255.255.255.0", isUp: up, isLoopback: loop)
        }
        XCTAssertEqual(IPv4Interface.wifiSubnet(from: [i("lo0", "127.0.0.1", loop: true), i("pdp_ip0", "10.1.1.1"),
                                                      i("en0", "192.168.1.9")])?.description, "192.168.1.0/24")
        // en0 down: first other up, non-loopback IPv4 interface.
        XCTAssertEqual(IPv4Interface.wifiSubnet(from: [i("lo0", "127.0.0.1", loop: true), i("en0", "192.168.1.9", up: false),
                                                      i("en1", "172.16.4.2")])?.description, "172.16.4.0/24")
        XCTAssertNil(IPv4Interface.wifiSubnet(from: [i("lo0", "127.0.0.1", loop: true)]))
        // Only en* (Wi-Fi/Ethernet): never cellular or a VPN tunnel.
        XCTAssertNil(IPv4Interface.wifiSubnet(from: [i("pdp_ip0", "10.1.1.1"), i("utun3", "10.8.0.2"), i("bridge100", "192.168.2.1")]))
    }

    func test_offer_outside_the_subnet_is_flagged() throws {
        let s = try XCTUnwrap(IPv4Subnet(address: "192.168.1.37", netmask: "255.255.255.0"))
        XCTAssertEqual(IPv4Subnet.mismatch(host: "192.168.60.11", subnet: s), s)
        XCTAssertNil(IPv4Subnet.mismatch(host: "192.168.1.200", subnet: s))
        XCTAssertNil(IPv4Subnet.mismatch(host: "fe80::1", subnet: s))
        XCTAssertNil(IPv4Subnet.mismatch(host: "192.168.60.11", subnet: nil))
    }

    // MARK: a real closed port fails fast

    func test_closed_local_port_fails_fast_as_refused() async throws {
        // Bind then close a listener so the port is known to be closed.
        let port = try Self.closedPort()
        let endpoint = try LanEndpoint(validating: "127.0.0.1", port: Int(port))
        let started = Date()
        do {
            _ = try await NWLanDialer(browseForPrompt: false).dial(endpoint, waitForNetwork: true)
            XCTFail("connected to a closed port")
        } catch let e as LanSocketError {
            XCTAssertEqual(e.kind, .refused, e.message)
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    static func closedPort() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET); addr.sin_port = 0; addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let ok = withUnsafeMutablePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) == 0 && getsockname(fd, $0, &len) == 0 }
        }
        guard ok else { throw POSIXError(.EADDRINUSE) }
        return UInt16(bigEndian: addr.sin_port)
    }
}
