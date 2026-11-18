import Foundation

/// The app side of `lgk mcp` (Windows `app/agent_gate_service.py` `dispatch`): one request from the agent socket,
/// answered by the gate. Replies carry no value: titles and domains, a grant id, a method and a note at most.
public enum AgentDispatch {
    /// Told to the agent with a passkey grant (agent-facing replies are English).
    public static let passkeyNote = "This login signs in with a passkey; the password is not filled. Open the site's sign-in "
        + "page and choose its passkey sign-in (for example 'Sign in with a passkey'). The user confirms it in "
        + "LocalGateKeys. Call fill_login with the grant to learn whether it went through."

    /// `_refused`: the English message the agent reads for each refusal ("Settings > Developer" names the Mac's own
    /// setting).
    public static func message(_ refusal: AgentRefusal) -> String {
        switch refusal {
        case .disabled: "AI agent access is off. Turn on Settings > Developer > Allow AI agents to use LocalGateKeys."
        case .pro: "AI agent access needs LocalGateKeys Pro."
        case .locked: "LocalGateKeys is locked. The user was asked to unlock it; try again after that."
        case .notFound: "No login the agent may use is saved for that site."
        case .denied: "The user did not approve this request."
        case .invalid: "The request is malformed."
        case .expired: "The grant expired or does not exist. Ask again with request_login."
        case .used: "The grant was already used. Ask again with request_login."
        case .notYours: "The grant belongs to another agent session."
        case .rateLimited: "Too many requests. Wait a minute, and ask once the user answered the open request."
        case .noTab: "No sign-in page for the approved site took the fill. Open the sign-in page and call fill_login again."
        case .noPasskey: "The site's passkey sign-in was not used yet. Choose the passkey sign-in on the approved site's "
            + "sign-in page, then call fill_login again."
        }
    }

    public static func refused(_ refusal: AgentRefusal) -> [String: JSONValue] {
        ["ok": .bool(false), "error": .string(refusal.rawValue), "message": .string(message(refusal))]
    }

    static func text(_ value: JSONValue?) -> String? {
        if case .string(let s)? = value { return s }
        return nil
    }

    /// One request (`{"action": "agent_*", "session", "client_name", ...}`) from the program `process` (the agent,
    /// from macOS, never from the request) whose connection has the process id `pid`.
    public static func reply(_ gate: AgentGate, request: [String: JSONValue], pid: Int32?, process: String) -> [String: JSONValue] {
        let session = text(request["session"]) ?? ""
        let client = AgentClient(clientID: "\(pid.map(String.init) ?? ""):\(AgentText.clean(session, limit: 64))",
                                 name: AgentText.clean(text(request["client_name"]), limit: 80),
                                 process: AgentText.clean(process, limit: 80))
        guard !session.isEmpty else { return refused(.invalid) }
        switch text(request["action"]) ?? "" {
        case "agent_list_sites":
            switch gate.listSites(client, query: text(request["query"]) ?? "") {
            case .failure(let refusal): return refused(refusal)
            case .success(let sites):
                return ["ok": .bool(true), "sites": .array(sites.map {
                    .object(["title": .string($0.title), "domain": .string($0.domain)])
                })]
            }
        case "agent_request_login":
            switch gate.requestLogin(client, site: text(request["site"]), purpose: text(request["purpose"])) {
            case .failure(let refusal): return refused(refusal)
            case .success(let grant):
                var reply: [String: JSONValue] = ["ok": .bool(true), "grant": .string(grant.id), "site": .string(grant.domain),
                                                  "expires_in": .int(300), "method": .string(grant.method.rawValue)]
                if grant.method == .passkey { reply["note"] = .string(passkeyNote) }
                return reply
            }
        case "agent_fill_login":
            switch gate.fillLogin(client, grant: text(request["grant"]),
                                  tabHint: AgentText.clean(text(request["tab_hint"]), limit: 200)) {
            case .failure(let refusal): return refused(refusal)
            case .success(let result):
                var reply: [String: JSONValue] = ["ok": .bool(true), "filled": .bool(result.filled), "site": .string(result.site),
                                                  "method": .string(result.method.rawValue)]
                if let note = result.note { reply["note"] = .string(note) }
                return reply
            }
        default:
            return ["ok": .bool(false), "error": .string("unknown_action"), "message": .string("Unknown command.")]
        }
    }
}
