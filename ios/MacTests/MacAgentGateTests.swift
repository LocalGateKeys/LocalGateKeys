import XCTest
import LGKCore
@testable import AppSharedMac

/// The Mac side of AI agents: what the gate may read from the vault, who the approval names, the settings keys.
@MainActor
final class MacAgentGateTests: XCTestCase {
    func testVaultForTheGateCarriesNoSecrets() throws {
        let login = try XCTUnwrap(VaultItem(id: "l1", record: [
            "kind": .string("web"), "title": .string("PayPal"), "username": .string("alice"),
            "password": .string("hunter2-pass"), "notes": .string("secret notes"), "favorite": .bool(true),
            "scope": .object(["ai_agents": .bool(true), "urls": .array([.object(["url": .string("https://www.paypal.com")])])]),
        ]))
        let passkey = try XCTUnwrap(VaultItem(id: "p1", record: [
            "kind": .string("passkey"), "title": .string("GitHub"),
            "payload": .object(["credential_id": .string("cred"), "relying_party_id": .string("github.com"),
                                "user_name": .string("octo"), "private_key": .string("KEY")]),
        ]))
        let vault = MacAgentVault(items: [login, passkey])
        XCTAssertEqual(vault.logins().map(\.id), ["l1"])
        XCTAssertEqual(Set(vault.logins()[0].record.keys), ["kind", "scope", "username", "favorite"])
        XCTAssertEqual(vault.passkeys(), [AgentPasskey(credentialID: "cred", rpID: "github.com", userName: "octo")])
        let dumped = String(describing: vault)
        for secret in ["hunter2-pass", "secret notes", "KEY"] { XCTAssertFalse(dumped.contains(secret), secret) }
    }

    func testApprovalNamesTheProgramThatStartedLgk() {
        XCTAssertEqual(AgentPeer(pid: 1, path: "/Applications/LocalGateKeys.app/Contents/MacOS/lgk",
                                 parentPath: "/usr/local/bin/claude", auditToken: nil).programName, "claude")
        XCTAssertEqual(AgentPeer(pid: 1, path: "/usr/bin/python3", parentPath: "/bin/zsh", auditToken: nil).programName, "python3")
        XCTAssertEqual(AgentPeer.unknown.programName, "")
        XCTAssertFalse(AgentPeerCheck.isSafariExtension(.unknown), "no audit token: refused")
    }

    func testSettingsAreOffByDefaultAndStayOnThisMac() {
        let suite = "lgk-agents-\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        XCTAssertEqual(DeveloperSettings.agentSettings(defaults), AgentGate.Settings(agentsEnabled: false, requireHello: false))
        defaults.set(true, forKey: DeveloperSettings.aiAgentsKey)
        XCTAssertTrue(DeveloperSettings.agentSettings(defaults).agentsEnabled)
        XCTAssertTrue(DeveloperSettings.aiAgentsKey.hasPrefix("settings.mac.developer."))
        XCTAssertTrue(AgentSocketNames.addCommand.hasSuffix("/Contents/MacOS/lgk\" mcp"))
    }

    func testAgentEventsPassTheActivityRules() {
        for event in ["agent.search", "agent.request", "agent.fill"] {
            XCTAssertNotNil(ActivityRecorder.Event(rawValue: event))
            XCTAssertNoThrow(try LocalData.safeEventType(event), event)
        }
        for result in ["ok", "denied", "locked", "not_found", "failed", "skipped", "open"] {
            XCTAssertNotNil(ActivityRecorder.Result(rawValue: result), result)
            XCTAssertTrue(LocalData.ActivityEvent.results.contains(result), result)
        }
    }
}
