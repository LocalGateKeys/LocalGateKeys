import Darwin
import XCTest
import LGKCore
@testable import AppSharedMac

/// docs/PENDING.md section 4, AI agents: "another program on `fill.sock` gets nothing". The real `fill.sock` sits in
/// the Safari app group's container, which macOS keeps other programs out of, so this runs the same server and
/// admission check (`AgentPeerCheck.isSafariExtension`) on a socket in a temporary folder and connects from this test
/// process, which is not the Safari extension: it must get no byte back. The same server without the check answers,
/// so the silence comes from the check.
final class AgentFillSocketTests: XCTestCase {
    private func roundTrip(admit: (@Sendable (AgentPeer) -> Bool)?) throws -> [UInt8] {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("lgkfs-\(UUID().uuidString.prefix(6))")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("fill.sock").path
        let server = AgentLineServer(label: "test.fill", admit: admit) { _, _ in
            ["ok": .bool(true), "username": .string("alice"), "password": .string("secret")]
        }
        XCTAssertEqual(server.start(path: path), .running)
        defer { server.stop() }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = AgentLineServer.address(path)
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(connected, 0, "the socket accepts the connection")
        let line = Array(#"{"action":"agent_release","url":"https://example.com/","grant":"x","entry_id":"y"}"#.utf8) + [0x0A]
        _ = line.withUnsafeBytes { write(fd, $0.baseAddress!, line.count) }
        var got: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
            if n <= 0 { break }
            got += chunk[0..<n]
        }
        return got
    }

    func testAnotherProgramOnFillSocketGetsNothing() throws {
        let got = try roundTrip(admit: { AgentPeerCheck.isSafariExtension($0) })
        XCTAssertEqual(got, [], "a program that is not the Safari extension gets no reply")
    }

    func testTheSameServerWithoutTheCheckAnswers() throws {
        let got = try roundTrip(admit: nil)
        XCTAssertTrue(String(decoding: got, as: UTF8.self).contains("secret"), "control: the handler's reply comes back")
    }
}
