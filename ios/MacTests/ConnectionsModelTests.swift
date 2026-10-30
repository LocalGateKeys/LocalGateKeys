import XCTest
@testable import AppSharedMac

@MainActor
final class ConnectionsModelTests: XCTestCase {
    final class Fake: ConnectionStateProviding {
        var safari: Bool?; var autoFill: Bool
        var opened: [String] = []
        init(safari: Bool?, autoFill: Bool) { self.safari = safari; self.autoFill = autoFill }
        func safariExtensionEnabled() async -> Bool? { safari }
        func autoFillEnabled() async -> Bool { autoFill }
        var safariOpens = true
        func openSafariSettings() async -> Bool { opened.append("safari"); return safariOpens }
        func openAutoFillSettings() { opened.append("autofill") }
    }

    private func model(_ s: Bool?, _ a: Bool) async -> ConnectionsModel {
        let m = ConnectionsModel(provider: Fake(safari: s, autoFill: a)); await m.refresh(); return m
    }

    func testHeadlineStates() async {
        let both = await model(true, true)
        XCTAssertEqual(both.headline, "Connected on this Mac"); XCTAssertEqual(both.tone, .success); XCTAssertEqual(both.status, "Ready")
        let one = await model(true, false)
        XCTAssertEqual(one.headline, "Connection needs attention"); XCTAssertEqual(one.tone, .warning)
        let other = await model(false, true)
        XCTAssertEqual(other.headline, "Connection needs attention")
        let none = await model(false, false)
        XCTAssertEqual(none.headline, "Connections need setup"); XCTAssertEqual(none.status, "Action needed")
        let unknown = await model(nil, true)
        XCTAssertEqual(unknown.tone, .warning)
    }

    func testRowsCopy() async {
        let m = await model(true, false)
        XCTAssertEqual(m.rows.map(\.title), ["Safari extension", "AutoFill", "Other browsers", "Wi-Fi sync"])
        XCTAssertEqual(m.rows[0].state, "Enabled"); XCTAssertEqual(m.rows[0].action, "Open Safari settings")
        XCTAssertEqual(m.rows[1].state, "Disabled"); XCTAssertEqual(m.rows[1].action, "Open AutoFill settings")
        XCTAssertEqual(m.rows[2].state, "Other browsers aren't supported on the Mac yet. Use Safari, or AutoFill in apps that support it.")
        let u = await model(nil, true)
        XCTAssertEqual(u.rows[0].state, "Unknown")
    }

    func testActionsAndRefreshFollowTheProvider() async {
        let fake = Fake(safari: false, autoFill: false)
        let m = ConnectionsModel(provider: fake)
        await m.refresh(); XCTAssertEqual(m.headline, "Connections need setup")
        fake.safari = true; fake.autoFill = true
        await m.refresh(); XCTAssertEqual(m.tone, .success)
        m.openAutoFillSettings(); XCTAssertEqual(fake.opened, ["autofill"])
    }

    func testPaletteHasDevicesAction() {
        XCTAssertTrue(PaletteModel.commands.contains { $0.action == .devices && $0.title == "Devices & connections" })
    }

    func testUnknownSafariSummary() async {
        let m = await model(nil, true)
        XCTAssertEqual(m.summary, "Safari didn't report the extension's state. Press Refresh.")
    }

    func testCheckingUntilFirstRefresh() async {
        let m = ConnectionsModel(provider: Fake(safari: true, autoFill: true))
        XCTAssertEqual(m.headline, "Checking…"); XCTAssertEqual(m.tone, .neutral)
        await m.refresh(); XCTAssertEqual(m.headline, "Connected on this Mac")
    }

    func testSafariOpenFailureShowsFallback() async {
        let fake = Fake(safari: true, autoFill: true); fake.safariOpens = false
        let m = ConnectionsModel(provider: fake)
        await m.openSafariSettings()
        XCTAssertEqual(m.message, "Open Safari › Settings › Extensions to turn on LocalGateKeys.")
        fake.safariOpens = true; await m.openSafariSettings(); XCTAssertNil(m.message)
    }

    /// The system calls completions on a background queue; the bridge must not trap there.
    func testBridgeResumesFromBackgroundQueue() async {
        let v: Bool? = await SystemConnectionState.bridge { done in
            DispatchQueue.global().async { done(true) }
        }
        XCTAssertEqual(v, true)
    }
}
