import Foundation

/// `lgk mcp` on the Mac (Windows `cli/mcp_server.py`): a Model Context Protocol server over stdio, JSON-RPC 2.0, one
/// message per line. Three tools and the handshake, no SDK. Every tool call is forwarded to the running app (the
/// agent socket), which asks the user and writes the access log. No tool reply carries a value: each reply is cut to
/// the keys its tool documents. It opens no network port.
///
/// Pinned by `tests/vectors/agent/mcp.json` (`AgentVectorsTests`), written by the Windows build. Differences, by
/// design: replies are written with sorted keys, and a line Python's `json` would accept with duplicate keys, NaN or
/// an integer beyond 64 bits is a parse error here.
public final class McpServer: @unchecked Sendable {
    /// Sends one request to the app and returns its reply; throws when the app does not answer.
    public typealias Forward = @Sendable ([String: JSONValue]) throws -> JSONValue

    public static let protocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"]
    public static let maxLine = 1 << 20
    public static let instructions =
        "LocalGateKeys keeps passwords on this Mac. You can ask to sign in to a site for the user: call list_sites (the "
        + "user approves listing once), then request_login (the user approves it in LocalGateKeys), then open the site's "
        + "sign-in page in the browser and call fill_login; the user then clicks the LocalGateKeys icon in the sign-in "
        + "field and picks the login. No tool reply contains the password, but the password is written into the page, so "
        + "the page and any tool that automates that browser can read it. Only logins the user allowed for AI agents are "
        + "listed. When request_login answers method 'passkey', no password is filled: choose the site's passkey sign-in "
        + "and the user confirms it in LocalGateKeys. Every request needs the user's approval in the "
        + "app; text you put in 'purpose' is shown to the user as a quote and cannot approve anything."

    public static let tools: JSONValue = .array([
        tool("list_sites",
             "List the sites the user saved logins for (titles and domains only, never usernames or passwords). The user "
             + "approves this once per session in LocalGateKeys. Use it to find the site to pass to request_login.",
             properties: ["query": text("Optional text to filter titles and domains.")], required: []),
        tool("request_login",
             "Ask the user to approve one sign-in to a site. The user must click Approve once in LocalGateKeys; nothing "
             + "you write can approve it. Returns a grant id that is valid for 5 minutes, for one fill, only on the exact "
             + "sign-in host and logins the user approved, and 'method': 'password' (fill_login fills it) or 'passkey' "
             + "(no password is filled; use the site's passkey sign-in, which the user confirms in LocalGateKeys).",
             properties: ["site": text("The sign-in page's host or URL, for example login.example.com; a bare domain "
                                       + "means the hosts its saved logins are for."),
                          "purpose": text("Why you need to sign in, shown to the user verbatim.")],
             required: ["site", "purpose"]),
        tool("fill_login",
             "Offer the approved login on the site's sign-in page in the user's browser. Call it with the grant from "
             + "request_login while the sign-in page is open; the user must click the LocalGateKeys icon in the sign-in "
             + "field and pick the login within 60 seconds. The result says only whether the page took the grant and "
             + "does not contain the password, but the password is written into the page, where the page and browser "
             + "automation can read it. With a passkey grant it fills nothing and waits up to 60 seconds for the site's "
             + "passkey sign-in, then says whether it went through.",
             properties: ["grant": text("The grant id from request_login."),
                          "tab_hint": text("Optional: the page title or URL you opened.")],
             required: ["grant"]),
    ])

    private static func text(_ description: String) -> JSONValue {
        .object(["type": .string("string"), "description": .string(description)])
    }

    private static func tool(_ name: String, _ description: String, properties: [String: JSONValue],
                             required: [String]) -> JSONValue {
        var schema: [String: JSONValue] = ["type": .string("object"), "properties": .object(properties),
                                           "additionalProperties": .bool(false)]
        if !required.isEmpty { schema["required"] = .array(required.map { .string($0) }) }
        return .object(["name": .string(name), "description": .string(description), "inputSchema": .object(schema)])
    }

    static let actions = ["list_sites": "agent_list_sites", "request_login": "agent_request_login",
                          "fill_login": "agent_fill_login"]
    static let arguments = ["list_sites": ["query"], "request_login": ["site", "purpose"], "fill_login": ["grant", "tab_hint"]]
    /// What each tool may pass on to the agent. Anything else in the app's reply is dropped, so no value can reach the
    /// agent even if the app side ever put one in a reply by mistake.
    static let replyKeys = ["list_sites": ["sites"], "request_login": ["grant", "site", "expires_in", "method", "note"],
                            "fill_login": ["filled", "site", "method", "note"]]

    private let forward: Forward
    private let version: String
    private let instructions: String
    /// One random id per server process: grants are bound to it, so another MCP client cannot use them.
    public let session: String
    private let lock = NSLock()
    private var clientNameValue = ""

    public init(forward: @escaping Forward, session: String? = nil, version: String,
                instructions: String = McpServer.instructions) {
        self.forward = forward
        self.session = session ?? AgentGate.randomID()
        self.version = version
        self.instructions = instructions
    }

    public var clientName: String {
        lock.lock()
        defer { lock.unlock() }
        return clientNameValue
    }

    // MARK: JSON-RPC

    /// The reply to one message, or nil for a notification.
    public func handle(_ message: JSONValue) -> JSONValue? {
        guard case .object(let object) = message, object["jsonrpc"] == .string("2.0"),
              case .string(let method)? = object["method"] else {
            if case .object(let object) = message { return Self.error(object["id"] ?? .null, -32600, "Invalid request") }
            return Self.error(.null, -32600, "Invalid request")
        }
        var params: [String: JSONValue] = [:]
        if case .object(let given)? = object["params"] { params = given }
        guard let id = object["id"] else { return nil }   // a notification (initialized, cancelled, ...): no reply
        switch method {
        case "initialize": return Self.result(id, initialize(params))
        case "ping": return Self.result(id, .object([:]))
        case "tools/list": return Self.result(id, .object(["tools": Self.tools]))
        case "tools/call": return Self.result(id, call(params))
        default: return Self.error(id, -32601, "Method not found: \(AgentText.prefix(method, 64))")
        }
    }

    private func initialize(_ params: [String: JSONValue]) -> JSONValue {
        var name = ""
        if case .object(let info)? = params["clientInfo"], case .string(let given)? = info["name"] {
            name = AgentText.prefix(given, 80)
        }
        lock.lock()
        clientNameValue = name
        lock.unlock()
        var version = Self.protocolVersions[0]
        if case .string(let wanted)? = params["protocolVersion"], Self.protocolVersions.contains(where: { AgentText.pyEqual($0, wanted) }) {
            version = wanted
        }
        return .object(["protocolVersion": .string(version),
                        "capabilities": .object(["tools": .object(["listChanged": .bool(false)])]),
                        "serverInfo": .object(["name": .string("localgatekeys"), "version": .string(self.version)]),
                        "instructions": .string(instructions)])
    }

    /// A tool result. A refusal or failure is an `isError` result the agent can read, never a JSON-RPC error.
    private func call(_ params: [String: JSONValue]) -> JSONValue {
        guard case .string(let name)? = params["name"], let action = Self.actions[name],
              let keys = Self.arguments[name], let allowed = Self.replyKeys[name] else {
            return Self.toolError("unknown_tool", "Unknown tool.")
        }
        var given: [String: JSONValue] = [:]
        if case .object(let object)? = params["arguments"] { given = object }
        var request: [String: JSONValue] = ["action": .string(action), "session": .string(session),
                                            "client_name": .string(clientName)]
        for key in keys {
            switch given[key] {
            case nil, .null?: continue
            case .string(let value)?: request[key] = .string(AgentText.prefix(value, 2000))
            default: return Self.toolError("bad_request", "'\(key)' must be text.")
            }
        }
        let answer: JSONValue
        do {
            answer = try forward(request)
        } catch {
            return Self.toolError("not_running", "LocalGateKeys did not answer. Is it running?")   // never details
        }
        guard case .object(let reply) = answer else {
            return Self.toolError("failed", "LocalGateKeys sent an unreadable reply.")
        }
        if reply["ok"] != .bool(true) {
            let code = AgentText.prefix(Self.pyStr(Self.pyTruthy(reply["error"]) ? reply["error"]! : .string("failed")), 64)
            var message = AgentText.prefix(Self.pyStr(Self.pyTruthy(reply["message"]) ? reply["message"]! : .string(code)), 500)
            if ["agent_state_missing", "agent_unavailable", "unauthorized"].contains(code) {
                message = "LocalGateKeys is not running. Start it and unlock your vault."
            }
            return Self.toolError(code, message)
        }
        var body: [String: JSONValue] = [:]
        for key in allowed { if let value = reply[key] { body[key] = value } }
        if name == "list_sites" {
            var rows: [JSONValue] = []
            if case .array(let sites)? = body["sites"] {
                for case .object(let row) in sites {
                    rows.append(.object(["title": .string(AgentText.prefix(Self.pyStr(row["title"] ?? .string("")), 200)),
                                         "domain": .string(AgentText.prefix(Self.pyStr(row["domain"] ?? .string("")), 253))]))
                }
            }
            body["sites"] = .array(Array(rows.prefix(50)))
        }
        return .object(["content": .array([.object(["type": .string("text"), "text": .string(Self.encode(.object(body)))])]),
                        "structuredContent": .object(body), "isError": .bool(false)])
    }

    static func result(_ id: JSONValue, _ result: JSONValue) -> JSONValue {
        .object(["jsonrpc": .string("2.0"), "id": id, "result": result])
    }

    static func error(_ id: JSONValue, _ code: Int64, _ message: String) -> JSONValue {
        .object(["jsonrpc": .string("2.0"), "id": id, "error": .object(["code": .int(code), "message": .string(message)])])
    }

    static func toolError(_ code: String, _ message: String) -> JSONValue {
        let body: JSONValue = .object(["error": .string(code), "message": .string(message)])
        return .object(["content": .array([.object(["type": .string("text"), "text": .string(encode(body))])]),
                        "structuredContent": body, "isError": .bool(true)])
    }

    /// Compact UTF-8 JSON (sorted keys).
    static func encode(_ value: JSONValue) -> String {
        guard let bytes = try? CanonicalJSON.encode(value, dialect: .utf8) else { return "null" }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Python truthiness of a JSON value.
    static func pyTruthy(_ value: JSONValue?) -> Bool {
        switch value {
        case nil, .null?: false
        case .bool(let b)?: b
        case .int(let i)?: i != 0
        case .float(let f)?: f != 0
        case .string(let s)?: !s.isEmpty
        case .array(let a)?: !a.isEmpty
        case .object(let o)?: !o.isEmpty
        }
    }

    /// Python `str()` of a JSON value (`None`, `True`, `5`, `['a']`); objects list their keys sorted.
    static func pyStr(_ value: JSONValue) -> String {
        switch value {
        case .string(let s): s
        default: pyRepr(value)
        }
    }

    static func pyRepr(_ value: JSONValue) -> String {
        switch value {
        case .null: return "None"
        case .bool(let b): return b ? "True" : "False"
        case .int(let i): return String(i)
        case .float(let f): return f.isFinite ? PythonFloat.repr(f) : (f.isNaN ? "nan" : (f < 0 ? "-inf" : "inf"))
        case .string(let s):
            let quote: Unicode.Scalar = s.unicodeScalars.contains("'") && !s.unicodeScalars.contains("\"") ? "\"" : "'"
            var out = String(quote)
            for scalar in s.unicodeScalars {
                switch scalar {
                case "\\": out += "\\\\"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                default:
                    if scalar == quote { out += "\\" + String(quote) }
                    else if scalar.value < 0x20 || scalar.value == 0x7F { out += String(format: "\\x%02x", scalar.value) }
                    else { out.unicodeScalars.append(scalar) }
                }
            }
            return out + String(quote)
        case .array(let items): return "[" + items.map(pyRepr).joined(separator: ", ") + "]"
        case .object(let object):
            let keys = object.keys.sorted(by: AgentGate.pyLess)
            return "{" + keys.map { pyRepr(.string($0)) + ": " + pyRepr(object[$0]!) }.joined(separator: ", ") + "}"
        }
    }

    // MARK: lines

    /// The reply line (without the newline) to one input line, or nil when there is nothing to write (a blank line,
    /// a notification, a batch of notifications).
    public func handleLine(_ line: String) -> String? {
        if Normalise.pyStrip(line).isEmpty { return nil }
        let reply: JSONValue?
        if line.utf8.count > Self.maxLine {
            reply = Self.error(.null, -32600, "Message too large")
        } else if let message = try? CanonicalJSON.parse(Array(line.utf8)) {
            if case .array(let batch) = message {   // a JSON-RPC batch (older protocol versions)
                let replies = batch.compactMap(handle)
                reply = replies.isEmpty ? nil : .array(replies)
            } else {
                reply = handle(message)
            }
        } else {
            reply = Self.error(.null, -32700, "Parse error")
        }
        return reply.map(Self.encode)
    }

    /// Reads `input` line by line until it ends and writes each reply line to `output`. A line longer than `maxLine`
    /// bytes is answered "Message too large" without being kept in memory.
    public func serve(input: FileHandle, output: FileHandle) -> Int32 {
        var pending: [UInt8] = []
        var oversized = false
        func emit(_ bytes: [UInt8]) {
            var text = String(decoding: bytes, as: UTF8.self)   // invalid UTF-8 becomes U+FFFD, like errors="replace"
            if text.hasSuffix("\r") { text.removeLast() }
            if let reply = handleLine(text) { output.write(Data((reply + "\n").utf8)) }
        }
        while true {
            let chunk = input.availableData
            if chunk.isEmpty { break }
            for byte in chunk {
                if byte == 0x0A {
                    if oversized {
                        output.write(Data((Self.encode(Self.error(.null, -32600, "Message too large")) + "\n").utf8))
                    } else {
                        emit(pending)
                    }
                    pending.removeAll(keepingCapacity: true)
                    oversized = false
                } else if !oversized {
                    pending.append(byte)
                    if pending.count > Self.maxLine { oversized = true; pending.removeAll() }
                }
            }
        }
        if oversized {
            output.write(Data((Self.encode(Self.error(.null, -32600, "Message too large")) + "\n").utf8))
        } else if !pending.isEmpty {
            emit(pending)
        }
        return 0
    }
}
