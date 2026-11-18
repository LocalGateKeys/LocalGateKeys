import XCTest
@testable import LGKCore

/// The SSH agent codec (Windows `ssh_agent/protocol.py`).
final class AgentProtocolTests: XCTestCase {
    func testProtocolRoundTrip() throws {
        let bind = SSHSessionBind(hostKey: [1, 2], sessionID: [3], signature: [4, 5, 6], forwarding: true)
        let messages = [
            SSHAgentMessage(type: SSHAgentProtocol.requestIdentities),
            SSHAgentMessage(type: SSHAgentProtocol.identitiesAnswer,
                            identities: [SSHAgentIdentity(blob: [9, 9], comment: "laptop \u{2713}"), SSHAgentIdentity(blob: [], comment: "")]),
            SSHAgentMessage(type: SSHAgentProtocol.signRequest, keyBlob: [1, 2, 3], data: [4, 5], flags: SSHKey.rsaSHA512),
            SSHAgentMessage(type: SSHAgentProtocol.signResponse, signature: [7, 8]),
            SSHAgentMessage(type: SSHAgentProtocol.extensionRequest, extensionName: SSHAgentProtocol.sessionBind, bind: bind),
            SSHAgentMessage(type: SSHAgentProtocol.extensionRequest, extensionName: "query", contents: [1, 2]),
            SSHAgentMessage(type: SSHAgentProtocol.failure),
            SSHAgentMessage(type: SSHAgentProtocol.success),
        ]
        for message in messages {
            let frame = try SSHAgentCodec.encode(message)
            XCTAssertEqual(try SSHAgentCodec.bodyLength(header: Array(frame.prefix(4))), frame.count - 4)
            XCTAssertEqual(try SSHAgentCodec.decode(frame), message)
        }
        // The exact bytes of a SIGN_REQUEST: length, type 13, string(blob), string(data), flags.
        XCTAssertEqual(try SSHAgentCodec.encode(SSHAgentMessage(type: 13, keyBlob: [0xAA], data: [0xBB, 0xCC], flags: 2)),
                       [0, 0, 0, 16, 13, 0, 0, 0, 1, 0xAA, 0, 0, 0, 2, 0xBB, 0xCC, 0, 0, 0, 2])
        XCTAssertEqual(try SSHAgentCodec.encode(SSHAgentMessage(type: SSHAgentProtocol.failure)), [0, 0, 0, 1, 5])
    }

    func testUnsupportedRequestsDecodeAsTypeOnly() throws {
        // ADD_IDENTITY (17) with contents, REMOVE_ALL (19), LOCK (22), ADD_ID_CONSTRAINED (25): the type only.
        let types: [UInt8] = [17, 19, 22, 25]
        for type in types {
            XCTAssertEqual(try SSHAgentCodec.decode([0, 0, 0, 3, type, 1, 2]), SSHAgentMessage(type: type))
        }
    }

    func testFramingErrors() {
        XCTAssertThrowsError(try SSHAgentCodec.bodyLength(header: [0, 0, 0, 0]))           // an empty frame
        XCTAssertThrowsError(try SSHAgentCodec.bodyLength(header: [0, 4, 0, 1]))           // 256 KiB + 1
        XCTAssertNoThrow(try SSHAgentCodec.bodyLength(header: [0, 4, 0, 0]))               // exactly 256 KiB
        XCTAssertThrowsError(try SSHAgentCodec.bodyLength(header: [0, 0, 1]))
        XCTAssertThrowsError(try SSHAgentCodec.decode([0, 0, 0, 5, 13, 0, 0, 0]))          // length mismatch
        XCTAssertThrowsError(try SSHAgentCodec.decode([0, 0, 0, 5, 13, 0, 0, 0, 9]))       // a truncated string
        XCTAssertThrowsError(try SSHAgentCodec.decode([0, 0, 0, 5, 12, 0, 0, 4, 1]))       // 1025 identities
        XCTAssertThrowsError(try SSHAgentCodec.encode(SSHAgentMessage(type: 14, signature: [UInt8](repeating: 0, count: 256 * 1024))))
    }
}
