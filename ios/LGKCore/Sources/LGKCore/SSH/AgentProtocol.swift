import Foundation

// Port of the Windows `ssh_agent/protocol.py`: the SSH agent message codec (draft-miller-ssh-agent). A frame is
// `uint32 length || byte type || contents`. The agent serves REQUEST_IDENTITIES, SIGN_REQUEST and the
// `session-bind@openssh.com` extension; every other request decodes as a message with only its type, which the server
// answers with FAILURE. Any framing or parse error throws `SSHAgentProtocolError` and the server closes the connection
// without a reply. Errors never carry message bytes.

public enum SSHAgentProtocol {
    public static let failure: UInt8 = 5
    public static let success: UInt8 = 6
    public static let requestIdentities: UInt8 = 11
    public static let identitiesAnswer: UInt8 = 12
    public static let signRequest: UInt8 = 13
    public static let signResponse: UInt8 = 14
    public static let extensionRequest: UInt8 = 27
    public static let sessionBind = "session-bind@openssh.com"
    /// Windows `MAX_FRAME`: 256 KiB.
    public static let maxFrame = 256 * 1024
    public static let maxIdentities = 1024
}

/// A frame that cannot be read; the connection is closed.
public struct SSHAgentProtocolError: Error, Equatable, Sendable {
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
}

public struct SSHAgentIdentity: Equatable, Sendable {
    public let blob: [UInt8]
    public let comment: String
    public init(blob: [UInt8], comment: String) { self.blob = blob; self.comment = comment }
}

public struct SSHSessionBind: Equatable, Sendable {
    public let hostKey: [UInt8]
    public let sessionID: [UInt8]
    public let signature: [UInt8]
    public let forwarding: Bool
    public init(hostKey: [UInt8], sessionID: [UInt8], signature: [UInt8], forwarding: Bool) {
        self.hostKey = hostKey; self.sessionID = sessionID; self.signature = signature; self.forwarding = forwarding
    }
}

public struct SSHAgentMessage: Equatable, Sendable {
    public var type: UInt8
    public var identities: [SSHAgentIdentity]
    public var keyBlob: [UInt8]
    public var data: [UInt8]
    public var flags: UInt32
    public var signature: [UInt8]
    public var extensionName: String
    public var contents: [UInt8]
    public var bind: SSHSessionBind?

    public init(type: UInt8, identities: [SSHAgentIdentity] = [], keyBlob: [UInt8] = [], data: [UInt8] = [], flags: UInt32 = 0,
                signature: [UInt8] = [], extensionName: String = "", contents: [UInt8] = [], bind: SSHSessionBind? = nil) {
        self.type = type; self.identities = identities; self.keyBlob = keyBlob; self.data = data; self.flags = flags
        self.signature = signature; self.extensionName = extensionName; self.contents = contents; self.bind = bind
    }
}

public enum SSHAgentCodec {
    /// The body length a 4-byte frame header announces; an empty or oversize frame closes the connection.
    public static func bodyLength(header: [UInt8]) throws -> Int {
        guard header.count == 4 else { throw SSHAgentProtocolError("truncated header") }
        let length = Int(header[0]) << 24 | Int(header[1]) << 16 | Int(header[2]) << 8 | Int(header[3])
        guard length > 0, length <= SSHAgentProtocol.maxFrame else { throw SSHAgentProtocolError("frame length out of range") }
        return length
    }

    /// Decodes one whole frame (header included). Trailing bytes inside a known message are ignored, as OpenSSH does.
    public static func decode(_ frame: [UInt8]) throws -> SSHAgentMessage {
        let length = try bodyLength(header: Array(frame.prefix(4)))
        guard frame.count == 4 + length else { throw SSHAgentProtocolError("frame length mismatch") }
        let kind = frame[4]
        var body = SSHWire.Reader(Array(frame[5...]))
        do {
            switch kind {
            case SSHAgentProtocol.signRequest:
                let blob = try body.string()
                let data = try body.string()
                let flags = try body.u32()
                return SSHAgentMessage(type: kind, keyBlob: blob, data: data, flags: flags)
            case SSHAgentProtocol.identitiesAnswer:
                let count = try body.u32()
                guard count <= UInt32(SSHAgentProtocol.maxIdentities) else { throw SSHAgentProtocolError("too many identities") }
                var identities: [SSHAgentIdentity] = []
                for _ in 0..<count {
                    let blob = try body.string()
                    let comment = try body.string()
                    identities.append(SSHAgentIdentity(blob: blob, comment: String(decoding: comment, as: UTF8.self)))
                }
                return SSHAgentMessage(type: kind, identities: identities)
            case SSHAgentProtocol.signResponse:
                return SSHAgentMessage(type: kind, signature: try body.string())
            case SSHAgentProtocol.extensionRequest:
                let name = String(decoding: try body.string(), as: UTF8.self)
                if name == SSHAgentProtocol.sessionBind {
                    let hostKey = try body.string()
                    let sessionID = try body.string()
                    let signature = try body.string()
                    let forwarding = try body.boolean()
                    return SSHAgentMessage(type: kind, extensionName: name, bind: SSHSessionBind(
                        hostKey: hostKey, sessionID: sessionID, signature: signature, forwarding: forwarding))
                }
                return SSHAgentMessage(type: kind, extensionName: name, contents: body.rest())
            default:
                return SSHAgentMessage(type: kind)   // REQUEST_IDENTITIES, SUCCESS, FAILURE and every unsupported request
            }
        } catch let error as SSHAgentProtocolError {
            throw error
        } catch {
            throw SSHAgentProtocolError("truncated message")
        }
    }

    public static func encode(_ message: SSHAgentMessage) throws -> [UInt8] {
        var body: [UInt8] = []
        switch message.type {
        case SSHAgentProtocol.identitiesAnswer:
            body = SSHWire.u32(UInt32(message.identities.count))
            for identity in message.identities { body += SSHWire.string(identity.blob) + SSHWire.string(identity.comment) }
        case SSHAgentProtocol.signRequest:
            body = SSHWire.string(message.keyBlob) + SSHWire.string(message.data) + SSHWire.u32(message.flags)
        case SSHAgentProtocol.signResponse:
            body = SSHWire.string(message.signature)
        case SSHAgentProtocol.extensionRequest:
            body = SSHWire.string(message.extensionName)
            if let bind = message.bind {
                body += SSHWire.string(bind.hostKey) + SSHWire.string(bind.sessionID) + SSHWire.string(bind.signature)
                body.append(bind.forwarding ? 1 : 0)
            } else {
                body += message.contents
            }
        default:
            break
        }
        let payload = [message.type] + body
        guard payload.count <= SSHAgentProtocol.maxFrame else { throw SSHAgentProtocolError("frame too large") }
        return SSHWire.u32(UInt32(payload.count)) + payload
    }
}
