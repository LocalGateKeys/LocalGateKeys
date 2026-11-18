import XCTest
@testable import LGKCore

/// The Local Agent Gate and `lgk mcp` against the Windows build: `tests/vectors/agent/{text,mcp,gate}.json`, written
/// by `scripts/make_agent_gate_vectors.py` from `agent_gate.py` and `cli/mcp_server.py`.
final class AgentVectorsTests: XCTestCase {
    var matcher: URLMatcher { URLMatcher(rules: URLMatchTests.rules) }

    static func load(_ name: String) throws -> JSONValue {
        let data = try Data(contentsOf: Vectors.shared("agent/\(name)"))
        return try CanonicalJSON.parse(Array(data))
    }

    // MARK: text.json

    func test_text_helpers_match_windows() throws {
        XCTAssertNotNil(URLMatchTests.rules, "public suffix list missing")
        let doc = try Self.load("text.json")
        for row in doc.at("clean_text").list {
            XCTAssertEqual(AgentText.clean(row.at("input").text, limit: Int(row.at("limit").number)), row.at("output").text,
                           "clean_text \(row.at("input"))")
        }
        for row in doc.at("sites").list {
            let site = row.at("input").text
            XCTAssertEqual(AgentText.registrableDomain(site, matcher: matcher), row.at("registrable_domain").optionalText,
                           "registrable_domain \(site)")
            XCTAssertEqual(AgentText.siteHost(site), row.at("site_host").optionalText, "site_host \(site)")
        }
        for row in doc.at("origin_domain").list {
            XCTAssertEqual(AgentText.originDomain(row.at("input").text, matcher: matcher), row.at("output").optionalText,
                           "origin_domain \(row.at("input"))")
        }
        for row in doc.at("agents_may_use").list {
            XCTAssertEqual(AgentText.agentsMayUse(row.at("entry").dict), row.at("output") == .bool(true), "\(row.at("entry"))")
        }
        let passkeys = doc.at("site_passkeys").at("passkeys").list.map(Self.passkey)
        for row in doc.at("site_passkeys").at("cases").list {
            let found = AgentText.sitePasskeys(username: row.at("username").text, hosts: row.at("hosts").list.map(\.text),
                                               domain: row.at("domain").text, passkeys: passkeys, matcher: matcher)
            XCTAssertEqual(found.sorted(by: AgentGate.pyLess), row.at("output").list.map(\.text), "site_passkeys \(row)")
        }
    }

    static func passkey(_ row: JSONValue) -> AgentPasskey {
        AgentPasskey(credentialID: row.at("credential_id").text, rpID: row.at("rp_id").text, userName: row.at("user_name").text)
    }

    // MARK: mcp.json

    /// The app's scripted replies, consumed in order.
    final class ScriptedApp: @unchecked Sendable {
        struct Down: Error {}
        let lock = NSLock()
        var replies: [JSONValue]
        var forwarded: [JSONValue] = []
        init(_ replies: [JSONValue]) { self.replies = replies }

        func forward(_ request: [String: JSONValue]) throws -> JSONValue {
            lock.lock()
            defer { lock.unlock() }
            forwarded.append(.object(request))
            guard !replies.isEmpty else { return .null }
            let reply = replies.removeFirst()
            if reply.at("$raise") == .bool(true) { throw Down() }
            if case .object(let object) = reply, let value = object["$value"] { return value }
            return reply
        }
    }

    /// Masks what the Mac says differently and parses each tool result's text (key order is not the contract).
    static func normalised(_ message: JSONValue) -> JSONValue {
        guard case .object(var object) = message, case .object(var result)? = object["result"] else { return message }
        if case .object(var info)? = result["serverInfo"] {
            info["version"] = .string("$version")
            result["serverInfo"] = .object(info)
            result["instructions"] = .string("$instructions")
        }
        if case .array(let content)? = result["content"] {
            result["content"] = .array(content.map { item in
                guard case .object(var part) = item, case .string(let text)? = part["text"],
                      let parsed = try? CanonicalJSON.parse(Array(text.utf8)) else { return item }
                part["text"] = parsed
                return .object(part)
            })
        }
        object["result"] = .object(result)
        return .object(object)
    }

    func test_mcp_server_matches_windows() throws {
        let doc = try Self.load("mcp.json")
        XCTAssertEqual(McpServer.protocolVersions, doc.at("protocol_versions").list.map(\.text))
        XCTAssertEqual(McpServer.maxLine, Int(doc.at("max_line").number))
        for test in doc.at("cases").list {
            let name = test.at("name").text
            let app = ScriptedApp(test.at("replies").list)
            let server = McpServer(forward: { try app.forward($0) }, session: "S1", version: "9.9.9")
            var output: [JSONValue] = []
            for line in test.at("lines").list.map(\.text) {
                guard let reply = server.handleLine(line) else { continue }
                output.append(Self.normalised(try CanonicalJSON.parse(Array(reply.utf8))))
            }
            let expected = test.at("output").list.map(Self.normalised)
            XCTAssertEqual(output.count, expected.count, name)
            for (got, want) in zip(output, expected) { XCTAssertEqual(got, want, name) }
            XCTAssertEqual(app.forwarded, test.at("forwarded").list, name)
            XCTAssertTrue(app.replies.isEmpty, "\(name): unused replies")
        }
    }

    func test_mcp_serve_reads_lines_and_refuses_oversized_ones() throws {
        let server = McpServer(forward: { _ in .object(["ok": .bool(true), "sites": .array([])]) }, session: "S1", version: "1")
        let input = Pipe(), output = Pipe()
        var bytes = Array("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n\n".utf8)
        bytes += [UInt8](repeating: 0x20, count: McpServer.maxLine + 10) + [0x0A]
        bytes += Array("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}".utf8)   // no final newline
        let handle = input.fileHandleForWriting, data = Data(bytes)
        let writer = Thread {
            handle.write(data)
            try? handle.close()
        }
        writer.start()
        XCTAssertEqual(server.serve(input: input.fileHandleForReading, output: output.fileHandleForWriting), 0)
        try output.fileHandleForWriting.close()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(text.split(separator: "\n").map(String.init), [
            #"{"id":1,"jsonrpc":"2.0","result":{}}"#,
            #"{"error":{"code":-32600,"message":"Message too large"},"id":null,"jsonrpc":"2.0"}"#,
            #"{"id":2,"jsonrpc":"2.0","result":{}}"#,
        ])
    }

    func test_tool_list_is_the_three_sign_in_tools_without_values() {
        let names = McpServer.tools.list.map { $0.at("name").text }
        XCTAssertEqual(names, ["list_sites", "request_login", "fill_login"])
        XCTAssertTrue(McpServer.instructions.contains("this Mac"))
        XCTAssertFalse(McpServer.instructions.contains("this PC"))
    }

    // MARK: gate.json

    struct Vault: AgentVault {
        let rows: [AgentLoginRecord]
        let keys: [AgentPasskey]
        func logins() -> [AgentLoginRecord] { rows }
        func passkeys() -> [AgentPasskey] { keys }
    }

    /// The fake app around one scenario's gate: settings, Pro, clock, approval view, access log, unlock prompts.
    final class Harness: @unchecked Sendable {
        var settings = AgentGate.Settings(agentsEnabled: true, requireHello: false)
        var pro = true
        var now: Double
        var vault: Vault?
        var answers: [Bool] = []
        var prompts: [[JSONValue]] = [[]]
        var log: [[JSONValue]] = [[]]
        var unlocks: [Int] = [0]
        var nextID = 0
        var during: [JSONValue] = []
        var duringOutputs: [JSONValue] = []
        var run: ((JSONValue) -> JSONValue)?
        var unexpected: [String] = []
        init(now: Double) { self.now = now }

        func confirm(_ request: AgentApprovalRequest) -> Bool {
            prompts[prompts.count - 1].append(.object([
                "action": .string(request.action.rawValue), "agent": .string(request.agent),
                "process": .string(request.process), "site": .string(request.site), "purpose": .string(request.purpose),
                "hello": .bool(request.hello), "method": .string(request.method.rawValue)]))
            guard !answers.isEmpty else {
                unexpected.append("unexpected prompt \(request)")
                return false
            }
            return answers.removeFirst()
        }

        func wait(_ grant: AgentGrant) -> Bool {
            let steps = during
            during = []
            for step in steps { duringOutputs.append(run?(step) ?? .null) }
            return grant.signal.isSet
        }
    }

    static func apply(_ settings: JSONValue, to harness: Harness) {
        guard case .object(let values) = settings else { return }
        if let on = values["agents_enabled"] { harness.settings.agentsEnabled = on == .bool(true) }
        if let hello = values["require_hello_for_agents"] { harness.settings.requireHello = hello == .bool(true) }
    }

    static func result(_ value: Result<AgentGrant, AgentRefusal>, now: Double) -> JSONValue {
        switch value {
        case .failure(let refusal): return .object(["refused": .string(refusal.rawValue)])
        case .success(let grant):
            func sorted(_ set: Set<String>) -> JSONValue { .array(set.sorted(by: AgentGate.pyLess).map { .string($0) }) }
            return .object(["grant": .string(grant.id), "domain": .string(grant.domain), "hosts": sorted(grant.hosts),
                            "entry_ids": sorted(grant.entryIDs), "passkey_ids": sorted(grant.passkeyIDs),
                            "method": .string(grant.method.rawValue), "expires_in": .float(grant.expires - now)])
        }
    }

    func test_gate_matches_windows() throws {
        let doc = try Self.load("gate.json")
        XCTAssertEqual(AgentGate.grantTTL, doc.at("constants").at("grant_ttl").number)
        XCTAssertEqual(AgentGate.armTTL, doc.at("constants").at("arm_ttl").number)
        XCTAssertEqual(Double(AgentGate.maxPurpose), doc.at("constants").at("max_purpose").number)
        XCTAssertEqual(Double(AgentText.maxSite), doc.at("constants").at("max_site").number)
        XCTAssertEqual(Double(AgentGate.maxListed), doc.at("constants").at("max_listed").number)
        XCTAssertEqual(AgentGate.rateWindow, doc.at("constants").at("rate_window").number)
        XCTAssertEqual(Double(AgentGate.ratePerClient), doc.at("constants").at("rate_per_client").number)
        XCTAssertEqual(Double(AgentGate.rateTotal), doc.at("constants").at("rate_total").number)
        let rows = doc.at("vault").list.map {
            AgentLoginRecord(id: $0.at("id").text, title: $0.at("title").text, kind: $0.at("kind").text, record: $0.at("record").dict)
        }
        let vault = Vault(rows: rows, keys: doc.at("passkeys").list.map(Self.passkey))
        var clients: [String: AgentClient] = [:]
        for (key, info) in doc.at("clients").dict {
            clients[key] = AgentClient(clientID: info.at("client_id").text, name: info.at("name").text,
                                       process: info.at("process").text)
        }
        for scenario in doc.at("scenarios").list {
            try replay(scenario, vault: vault, clients: clients, start: doc.at("start").number)
        }
    }

    private func replay(_ scenario: JSONValue, vault: Vault, clients: [String: AgentClient], start: Double) throws {
        let name = scenario.at("name").text
        let h = Harness(now: start)
        Self.apply(scenario.at("settings"), to: h)
        if scenario.at("pro") == .bool(false) { h.pro = false }
        h.vault = scenario.at("locked") == .bool(true) ? nil : vault
        let gate = AgentGate(session: { h.vault }, settings: { h.settings }, confirm: { h.confirm($0) },
                             activity: { h.log[h.log.count - 1].append(.array([.string($0), .string($1)])) },
                             isPro: { h.pro }, requestUnlock: { h.unlocks[h.unlocks.count - 1] += 1 },
                             clock: { h.now }, matcher: matcher,
                             newID: { h.nextID += 1; return "G\(h.nextID)" }, lockedWait: 0, fillWait: 0,
                             waitForFinish: { grant, _ in h.wait(grant) })

        func run(_ step: JSONValue) -> JSONValue {
            h.log.append([]); h.prompts.append([]); h.unlocks.append(0)
            if case .bool(let answer)? = step.dict["answer"] { h.answers = [answer] }
            var out: [String: JSONValue] = [:]
            let client = clients[step.at("client").text] ?? AgentClient(clientID: "", name: "", process: "")
            switch step.at("op").text {
            case "list_sites":
                switch gate.listSites(client, query: step.dict["query"]?.text ?? "") {
                case .failure(let refusal): out["result"] = .object(["refused": .string(refusal.rawValue)])
                case .success(let sites):
                    out["result"] = .object(["sites": .array(sites.map {
                        .object(["title": .string($0.title), "domain": .string($0.domain)])
                    })])
                }
            case "request_login":
                out["result"] = Self.result(gate.requestLogin(client, site: step.at("site").optionalText,
                                                              purpose: step.at("purpose").optionalText), now: h.now)
            case "fill_login":
                let grantID = step.at("grant").optionalText
                let known = grantID.flatMap(gate.grant) != nil
                h.during = known ? step.at("during").list : []
                if !known && !step.at("during").list.isEmpty { XCTFail("\(name): during on an unknown grant") }
                let outputsBefore = h.duringOutputs.count
                let value = gate.fillLogin(client, grant: grantID, tabHint: step.dict["tab_hint"]?.text ?? "")
                if !h.during.isEmpty { XCTFail("\(name): the fill never waited, so its during steps did not run") }
                h.during = []
                let nested = Array(h.duringOutputs[outputsBefore...])
                h.duringOutputs.removeSubrange(outputsBefore...)
                if !nested.isEmpty { out["during"] = .array(nested) }
                switch value {
                case .failure(let refusal): out["result"] = .object(["refused": .string(refusal.rawValue)])
                case .success(let fill):
                    var body: [String: JSONValue] = ["filled": .bool(fill.filled), "site": .string(fill.site),
                                                     "method": .string(fill.method.rawValue)]
                    if let note = fill.note { body["note"] = .string(note) }
                    out["result"] = .object(["fill": .object(body)])
                }
            case "take_for_origin":
                out["result"] = .object(["taken": gate.takeForOrigin(step.at("origin").text).map { .string($0.id) } ?? .null])
            case "take_passkey_for_origin":
                let taken = gate.takePasskeyForOrigin(step.at("origin").text, credentialIDs: step.at("credentials").list.map(\.text))
                out["result"] = .object(["taken": taken.map { .string($0.id) } ?? .null])
            case "passkey_pending":
                out["result"] = .object(["pending": .bool(gate.passkeyPending(step.at("origin").text))])
            case "finish":
                if let grant = gate.grant(step.at("grant").text) { gate.finish(grant, outcome: step.at("outcome").text) }
                else { XCTFail("\(name): finish on an unknown grant") }
            case "advance":
                h.now += step.at("seconds").number
            case "set":
                Self.apply(step.at("settings"), to: h)
                if case .bool(let pro)? = step.dict["pro"] { h.pro = pro }
            default:
                XCTFail("\(name): unknown op \(step.at("op"))")
            }
            if !h.answers.isEmpty { XCTFail("\(name): unused answer in \(step)"); h.answers = [] }
            out["prompts"] = .array(h.prompts.removeLast())
            out["log"] = .array(h.log.removeLast())
            out["unlocks"] = .int(Int64(h.unlocks.removeLast()))
            return .object(out)
        }
        h.run = run

        for (index, step) in scenario.at("steps").list.enumerated() {
            var got = run(step).dict
            let label = "\(name) step \(index + 1) (\(step.at("op").text))"
            let nested = got.removeValue(forKey: "during")?.list ?? []
            let wantNested = step.at("during").list
            XCTAssertEqual(nested.count, wantNested.count, "\(label): during steps")
            for (i, (a, b)) in zip(nested, wantNested).enumerated() {
                XCTAssertEqual(a, b.at("expect"), "\(label) during \(i + 1)")
            }
            XCTAssertEqual(JSONValue.object(got), step.at("expect"), label)
        }
        XCTAssertEqual(h.unexpected, [], name)
    }

    // MARK: Mac-only behaviour (no Windows counterpart)

    func makeGate(_ h: Harness, passkeyOutcomes: Bool) -> AgentGate {
        AgentGate(session: { h.vault }, settings: { h.settings }, confirm: { h.confirm($0) }, isPro: { h.pro },
                  clock: { h.now }, matcher: matcher, newID: { h.nextID += 1; return "G\(h.nextID)" }, lockedWait: 0,
                  fillWait: 0, passkeyOutcomes: passkeyOutcomes, waitForFinish: { grant, _ in h.wait(grant) })
    }

    func login(_ id: String, _ title: String, _ urls: [String], username: String = "alice",
               favorite: Bool = false) -> AgentLoginRecord {
        AgentLoginRecord(id: id, title: title, kind: "web", record: [
            "username": .string(username), "favorite": .bool(favorite),
            "scope": .object(["ai_agents": .bool(true), "urls": .array(urls.map {
                .object(["url": .string($0), "match": .string("exact_origin")])
            })]),
        ])
    }

    func test_passkey_grant_answers_at_once_when_the_ceremony_is_not_seen() {
        let h = Harness(now: 1000)
        h.vault = Vault(rows: [login("g", "GitHub", ["https://github.com"], username: "octo")],
                        keys: [AgentPasskey(credentialID: "pk", rpID: "github.com", userName: "octo")])
        let gate = makeGate(h, passkeyOutcomes: false)
        let client = AgentClient(clientID: "1:S", name: "Claude Code", process: "claude")
        h.answers = [true]
        guard case .success(let grant) = gate.requestLogin(client, site: "github.com", purpose: "PR") else {
            return XCTFail("no grant")
        }
        XCTAssertEqual(grant.method, .passkey)
        h.during = [.null]   // must not be waited on
        let result = gate.fillLogin(client, grant: grant.id)
        XCTAssertEqual(h.during, [.null])
        XCTAssertEqual(try result.get(), AgentFillResult(filled: false, site: "github.com", method: .passkey,
                                                         note: AgentGate.passkeyUnseenNote))
    }

    func test_dispatch_replies_carry_no_values() {
        let h = Harness(now: 1000)
        h.vault = Vault(rows: [login("p", "PayPal", ["https://www.paypal.com"])], keys: [])
        let gate = makeGate(h, passkeyOutcomes: false)
        h.answers = [true]
        let listed = AgentDispatch.reply(gate, request: ["action": .string("agent_list_sites"), "session": .string("S")],
                                         pid: 42, process: "claude")
        XCTAssertEqual(listed["sites"], .array([.object(["title": .string("PayPal"), "domain": .string("paypal.com")])]))
        XCTAssertEqual(h.prompts[0].first?.at("agent"), .string("MCP client"))
        h.answers = [true]
        let granted = AgentDispatch.reply(gate, request: [
            "action": .string("agent_request_login"), "session": .string("S"), "client_name": .string("Claude Code"),
            "site": .string("www.paypal.com"), "purpose": .string("Pay"),
        ], pid: 42, process: "claude")
        XCTAssertEqual(Set(granted.keys), ["ok", "grant", "site", "expires_in", "method"])
        XCTAssertEqual(granted["method"], .string("password"))
        // Another session (or another process) cannot use the grant.
        let other = AgentDispatch.reply(gate, request: ["action": .string("agent_fill_login"), "session": .string("T"),
                                                        "grant": granted["grant"]!], pid: 42, process: "claude")
        XCTAssertEqual(other["error"], .string("not_yours"))
        XCTAssertEqual(AgentDispatch.reply(gate, request: ["action": .string("agent_list_sites")], pid: 42, process: "x")["error"],
                       .string("invalid"))
        XCTAssertEqual(AgentDispatch.reply(gate, request: ["action": .string("reveal"), "session": .string("S")], pid: 42,
                                           process: "x")["error"], .string("unknown_action"))
        for refusal in AgentRefusal.allCases { XCTAssertFalse(AgentDispatch.message(refusal).isEmpty) }
    }

    func test_fill_offer_lists_approved_logins_in_picker_order() {
        let h = Harness(now: 1000)
        let rows = [login("b", "Example", ["https://login.example.com"], username: "bob"),
                    login("a", "Example", ["https://login.example.com"], username: "Alice", favorite: true),
                    login("c", "Example", ["https://login.example.com"], username: "carol"),
                    login("pk", "Example", ["https://login.example.com"], username: "dave"),
                    login("other", "Other", ["https://shop.example.com"])]
        h.vault = Vault(rows: rows, keys: [])
        let gate = makeGate(h, passkeyOutcomes: false)
        h.answers = [true]
        guard case .success(let grant) = gate.requestLogin(AgentClient(clientID: "1:S", name: "", process: ""),
                                                           site: "login.example.com", purpose: "x") else {
            return XCTFail("no grant")
        }
        XCTAssertEqual(grant.entryIDs, ["a", "b", "c", "pk"])
        // By now the owner turned "AI agents may use this login" off for "pk": it is not offered.
        var changed = rows
        changed[3] = AgentLoginRecord(id: "pk", title: "Example", kind: "web", record: ["username": .string("dave")])
        let later = Vault(rows: changed, keys: [])
        let choices = AgentFillOffer.choices(grant: grant, pageURL: "https://login.example.com/signin", vault: later,
                                             matcher: matcher)
        XCTAssertEqual(choices.map(\.entryID), ["a", "b", "c"])
        XCTAssertEqual(choices.first?.match, .exactOrigin)
        XCTAssertEqual(AgentFillOffer.choices(grant: grant, pageURL: "https://evil.example.org", vault: later,
                                              matcher: matcher), [])
    }

    func test_release_book_is_one_use_bound_to_origin_and_logins() {
        let clock = Box(0.0)
        let counter = Box(0)
        let book = AgentReleaseBook(clock: { clock.value }, newID: { counter.value += 1; return "T\(counter.value)" })
        XCTAssertNil(book.issue(origin: "http://login.example.com", entryIDs: ["a"]))
        XCTAssertNil(book.issue(origin: "https://login.example.com", entryIDs: []))
        let t1 = book.issue(origin: "https://login.example.com", entryIDs: ["a", "b"])!
        XCTAssertNil(book.take(token: t1, entryID: "a", origin: "https://evil.example.com"))
        XCTAssertNil(book.take(token: t1, entryID: "a", origin: "https://login.example.com"), "used up by the wrong pick")
        let t2 = book.issue(origin: "https://login.example.com", entryIDs: ["a", "b"])!
        XCTAssertNil(book.take(token: t2, entryID: "z", origin: "https://login.example.com"))
        let t3 = book.issue(origin: "https://login.example.com:443", entryIDs: ["a", "b"])!
        XCTAssertEqual(book.take(token: t3, entryID: "b", origin: "https://login.example.com"), "b")
        XCTAssertNil(book.take(token: t3, entryID: "b", origin: "https://login.example.com"))
        let t4 = book.issue(origin: "https://login.example.com", entryIDs: ["a"])!
        clock.value = AgentReleaseBook.ttl
        XCTAssertNil(book.take(token: t4, entryID: "a", origin: "https://login.example.com"))
    }

    func test_signal_wakes_a_waiter() {
        let signal = AgentSignal()
        XCTAssertFalse(signal.wait(timeout: 0.01))
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { signal.set() }
        XCTAssertTrue(signal.wait(timeout: 5))
        XCTAssertTrue(signal.isSet)
    }
}

/// A mutable value a `@Sendable` test closure can read.
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

private extension JSONValue {
    func at(_ key: String) -> JSONValue {
        if case .object(let object) = self { return object[key] ?? .null }
        return .null
    }
    var dict: [String: JSONValue] { if case .object(let o) = self { return o }; return [:] }
    var list: [JSONValue] { if case .array(let a) = self { return a }; return [] }
    var text: String { if case .string(let s) = self { return s }; return "" }
    var optionalText: String? { if case .string(let s) = self { return s }; return nil }
    var number: Double {
        switch self {
        case .int(let i): Double(i)
        case .float(let f): f
        default: .nan
        }
    }
}
