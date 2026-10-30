import XCTest
import LGKCore
@testable import AppShared

/// Pins the dictionaries that cross `SFExtensionMessageKey` between the Safari extension's
/// `background-safari.js` and `SafariSaveService.handle` (which `SafariWebExtensionHandler` calls).
/// The request keys are read from the committed web resources, so a change on either side fails here.
final class SafariHandlerContractTests: XCTestCase {
    var root: URL!
    var filesDir: URL!
    var vaultDir: URL!
    var keychain: InMemoryKeychainVault!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lgk-safari-contract-\(UUID().uuidString)", isDirectory: true)
        filesDir = root.appendingPathComponent("SafariSave", isDirectory: true)
        vaultDir = root.appendingPathComponent("Vault", isDirectory: true)
        try FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: vaultDir, withIntermediateDirectories: true)
        keychain = InMemoryKeychainVault()
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: root) }

    func makeService() -> SafariSaveService {
        let files: URL = filesDir, vault: URL = vaultDir
        let settings = AppSettings(defaults: UserDefaults(suiteName: "safari-contract-\(UUID().uuidString)")!)
        return SafariSaveService(keychain: keychain, files: { files }, vaultDirectory: { vault }, settings: settings,
                                 entitlement: FakeSafariEntitlement(false), now: { 1000 }, random: FixedRandom())
    }

    func storeKeys() throws {
        try keychain.write(.safariIndexKey, Array(repeating: UInt8(7), count: 32))
        try keychain.write(.safariInboxKey, Array(repeating: UInt8(8), count: 32))
    }

    /// ios/SafariSave/Resources/background-safari.js, found from this file's path (the simulator reads the
    /// Mac's file system).
    func backgroundSource() throws -> String {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("SafariSave/Resources/background-safari.js")
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Every `native({ ... })` object literal in the background: action name -> its keys.
    func nativeRequests(in source: String) throws -> [String: Set<String>] {
        let regex = try NSRegularExpression(pattern: #"native\(\{([^}]*)\}\)"#)
        var out: [String: Set<String>] = [:]
        let ns = source as NSString
        for match in regex.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
            var keys: Set<String> = []
            var action: String?
            for part in ns.substring(with: match.range(at: 1)).split(separator: ",") {
                let pieces = part.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                guard let key = pieces.first, !key.isEmpty else { continue }
                keys.insert(key)
                if key == "action", pieces.count == 2 { action = pieces[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"")) }
            }
            out[try XCTUnwrap(action, "a native request without a literal action")] = keys
        }
        return out
    }

    /// A request built from the background's key list, with the values a capture would carry.
    func request(_ action: String, keys: Set<String>, password: String = "pw1") -> [String: Any] {
        var values: [String: Any] = [:]
        for key in keys {
            switch key {
            case "action": values[key] = action
            case "origin": values[key] = "https://example.com"
            case "username": values[key] = "alex"
            case "password": values[key] = password
            case "status": values[key] = "new"
            case "other": values[key] = "https://login.example.com"
            default: XCTFail("unexpected request key \(key)")
            }
        }
        return values
    }

    /// Plist-compatible values only (they cross `SFExtensionMessageKey`): Strings and Bools.
    func assertPlistValues(_ reply: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
        for (key, value) in reply {
            XCTAssertTrue(value is String || value is Bool, "\(key) is \(type(of: value))", file: file, line: line)
        }
    }

    func test_background_sends_the_keys_the_service_reads() throws {
        let source = try backgroundSource()
        XCTAssertTrue(source.contains(#"const NATIVE_APP_ID = "app.localgatekeys.app";"#), "native message app id")
        let requests = try nativeRequests(in: source)
        XCTAssertEqual(requests, [
            "classify": ["action", "origin", "username", "password"],
            "save": ["action", "origin", "username", "password", "status"],
            "same_site": ["action", "origin", "other"],
        ])
    }

    func test_same_site_reply_is_same_only() async throws {
        let keys = try XCTUnwrap(try nativeRequests(in: try backgroundSource())["same_site"])
        let reply = await makeService().handle(request("same_site", keys: keys))
        XCTAssertEqual(Set(reply.keys), ["same"])
        XCTAssertNotNil(reply["same"] as? Bool)
        assertPlistValues(reply)
        // The background shows the capture only on a literal true.
        XCTAssertTrue(try backgroundSource().contains("r?.same === true"))
    }

    func test_classify_reply_is_status_only() async throws {
        let keys = try XCTUnwrap(try nativeRequests(in: try backgroundSource())["classify"])
        let s = makeService()

        let before = await s.handle(request("classify", keys: keys))
        XCTAssertEqual(Set(before.keys), ["status"])
        XCTAssertEqual(before["status"] as? String, "unavailable", "no keys yet")
        assertPlistValues(before)

        try storeKeys()
        let after = await s.handle(request("classify", keys: keys))
        XCTAssertEqual(Set(after.keys), ["status"])
        XCTAssertEqual(after["status"] as? String, "new")
        assertPlistValues(after)
    }

    func test_save_reply_is_stored_or_stored_and_error() async throws {
        let keys = try XCTUnwrap(try nativeRequests(in: try backgroundSource())["save"])
        let s = makeService()

        let refused = await s.handle(request("save", keys: keys))
        XCTAssertEqual(Set(refused.keys), ["stored", "error"])
        XCTAssertEqual(refused["stored"] as? Bool, false)
        XCTAssertEqual(refused["error"] as? String, "unavailable")
        assertPlistValues(refused)

        try storeKeys()
        let stored = await s.handle(request("save", keys: keys))
        XCTAssertEqual(Set(stored.keys), ["stored"])
        XCTAssertEqual(stored["stored"] as? Bool, true)
        assertPlistValues(stored)
    }

    func test_every_save_error_is_one_the_background_shows() throws {
        let source = try backgroundSource()
        for error in ["full", "inbox_full", "invalid", "unavailable"] {
            XCTAssertNotNil(SafariSaveService.SaveError(rawValue: error), error)
            XCTAssertTrue(source.contains("  get \(error)() { return tr(\""), "SAVE_ERRORS has \(error)")
        }
        for status in ["new", "exists", "full", "unavailable"] {
            XCTAssertNotNil(SafariSaveService.Status(rawValue: status), status)
        }
    }

    /// Audit 2026-10-24 M-3 / L-7: classify answers new / exists only, never a password comparison, and the
    /// background treats "exists" as a status it prompts for (the app compares the password at import).
    func test_classify_never_reports_a_password_comparison() throws {
        for status in ["exact", "password_changed"] {
            XCTAssertNil(SafariSaveService.Status(rawValue: status), status)
        }
        XCTAssertTrue(try backgroundSource().contains(#""exists""#), "background-safari.js knows the exists status")
    }

    func test_unknown_action_is_unsupported() async {
        let s = makeService()
        let reply = await s.handle(["action": "fill", "origin": "https://example.com"])
        XCTAssertEqual(reply.keys.sorted(), ["error"])
        XCTAssertEqual(reply["error"] as? String, "unsupported")
        let empty = await s.handle([:])
        XCTAssertEqual(empty["error"] as? String, "unsupported")
    }
}
