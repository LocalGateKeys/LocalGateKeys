import XCTest
import AppShared
@testable import LocalGateKeys

/// Records what the intent copies (no real pasteboard in tests).
@MainActor
final class FakeCodeClipboard: SecretCopying {
    var copied: [String] = []
    func copy(_ text: String) { copied.append(text) }
}

/// Sub-plan 06 task 3: the Shortcuts "Copy code" action reads only the pinned codes, and never gives an old code.
@MainActor
final class CopyCodeIntentTests: XCTestCase {
    let secretA = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    let secretB = "JBSWY3DPEHPK3PXP"
    let now = Date(timeIntervalSince1970: 1_700_000_010)
    var suiteName = ""
    var store: PinnedCodeStore!
    var keychain: MemoryPinKeychain!
    var clipboard: FakeCodeClipboard!

    override func setUp() async throws {
        suiteName = "copy-code-\(UUID().uuidString)"
        keychain = MemoryPinKeychain()
        store = PinnedCodeStore(defaults: UserDefaults(suiteName: suiteName)!, keychain: keychain)
        clipboard = FakeCodeClipboard()
        let store = self.store!, clipboard = self.clipboard!, now = self.now
        CodeIntentEnvironment.makeStore = { store }
        CodeIntentEnvironment.clipboard = { clipboard }
        CodeIntentEnvironment.now = { now }
    }

    override func tearDown() async throws {
        CodeIntentEnvironment.makeStore = { CodeIntentEnvironment.readOnlyStore() }
        CodeIntentEnvironment.clipboard = { CodeIntentEnvironment.appClipboard() }
        CodeIntentEnvironment.now = { Date() }
        UserDefaults().removePersistentDomain(forName: suiteName)
    }

    func codeA() -> WatchCode { WatchCode(id: "a", title: "GitHub", secret: secretA) }
    func codeB() -> WatchCode { WatchCode(id: "b", title: "Mail", secret: secretB) }

    /// Pins a and b (in that order) and stores their secrets, plus an unpinned code that must never appear.
    func pinTwo() {
        store.pinnedIDs = ["a", "b"]
        store.replace([codeA(), codeB(), WatchCode(id: "c", title: "Bank", secret: secretB)])
    }

    func intent(_ id: String, title: String? = nil) -> CopyCodeIntent {
        var intent = CopyCodeIntent()
        intent.item = CodeEntity(id: id, title: title)
        return intent
    }

    func testSuggestedEntitiesArePinnedCodesInPinOrder() async throws {
        pinTwo()
        let entities = try await CodeEntityQuery().suggestedEntities()
        XCTAssertEqual(entities.map(\.id), ["a", "b"])
        XCTAssertEqual(entities.map(\.title), ["GitHub", "Mail"])
    }

    func testSuggestedEntitiesEmptyWhenNothingPinnedOrForgotten() async throws {
        let none = try await CodeEntityQuery().suggestedEntities()
        XCTAssertTrue(none.isEmpty)
        pinTwo()
        store.forgetSecrets()
        let forgotten = try await CodeEntityQuery().suggestedEntities()
        XCTAssertTrue(forgotten.isEmpty)
    }

    func testEntitiesForIdentifiersKeepOnlyShownPins() async throws {
        pinTwo()
        let found = try await CodeEntityQuery().entities(for: ["b", "c", "x"])   // c: stored once, never pinned
        XCTAssertEqual(found.map(\.id), ["b"])
        XCTAssertEqual(found.first?.title, "Mail")
        store.forgetSecrets()
        let untitled = try await CodeEntityQuery().entities(for: ["a"])
        XCTAssertEqual(untitled.map(\.id), ["a"])
        XCTAssertNil(untitled.first?.title)   // still resolvable, so perform can say why there is no code
    }

    func testCopiesTheSameDigitsAsWatchCode() async throws {
        pinTwo()
        let expected = try XCTUnwrap(codeB().current(at: 1_700_000_010)).code
        XCTAssertEqual(expected.count, 6)
        _ = try await intent("b").perform()
        XCTAssertEqual(clipboard.copied, [expected])
        XCTAssertEqual(try CopyCodeIntent.currentCode(for: "b", store: store, at: now), expected)
    }

    func testFailsAfterForgetOnLockExpiry() async throws {
        pinTwo()
        store.expiresAt = now
        await assertFails(intent("a"), with: .unavailable)
    }

    func testFailsWhenSecretsCannotBeRead() async throws {
        pinTwo()
        store.forgetSecrets()
        await assertFails(intent("a"), with: .unavailable)
    }

    func testFailsForAnUnpinnedOrUnshownCode() async throws {
        pinTwo()
        await assertFails(intent("c"), with: .notPinned)   // its secret was offered but it is not pinned
        store.pinnedIDs = ["p1", "p2", "p3", "p4", "a"]
        store.replace(["p1", "p2", "p3", "p4"].map { WatchCode(id: $0, title: $0, secret: secretB) } + [codeA()])
        await assertFails(intent("a"), with: .notPinned)   // fifth code: widgets and Shortcuts show only four
    }

    func testRequiresAnUnlockedDevice() {
        guard case .requiresAuthentication = CopyCodeIntent.authenticationPolicy else {
            return XCTFail("Copy code must not run on a locked device")
        }
        XCTAssertFalse(CopyCodeIntent.openAppWhenRun)
    }

    /// PENDING iPhone "Siri": the dialog Siri speaks and shows is "Code copied" only, never the digits (the
    /// digits are the shortcut's return value).
    func testDialogSaysCodeCopiedWithoutTheDigits() async throws {
        pinTwo()
        let expected = try XCTUnwrap(codeA().current(at: 1_700_000_010)).code
        let result = try await intent("a").perform()
        XCTAssertFalse(String(reflecting: result).contains(expected) && !String(reflecting: result).contains("value"),
                       "the code is only the return value")
        for locale in ["en", "de"] {
            var r = CopyCodeIntent.copiedDialog
            r.locale = Locale(identifier: locale)
            let text = String(localized: r)
            XCTAssertFalse(text.contains(where: \.isNumber), "the dialog holds no digits: \(text)")
            XCTAssertEqual(text, locale == "en" ? "Code copied" : "Code kopiert")
        }
    }

    /// PENDING iPhone "Siri", one other language: the title, both errors, "Code copied" and the Siri phrase in German.
    func testGermanTitleErrorsDialogAndPhrase() throws {
        func de(_ resource: LocalizedStringResource) -> String {
            var r = resource
            r.locale = Locale(identifier: "de")
            return String(localized: r)
        }
        XCTAssertEqual(de(CopyCodeIntent.title), "Code kopieren")
        XCTAssertEqual(de(CopyCodeError.unavailable.localizedStringResource), "LocalGateKeys öffnen, um Codes anzuzeigen")
        let notPinned = de(CopyCodeError.notPinned.localizedStringResource)
        XCTAssertTrue(notPinned.contains("2FA-Code") && notPinned.contains("\(PinnedCodeStore.maxShown)"), notPinned)
        XCTAssertEqual(de("Code copied"), "Code kopiert")
        let phrases = try XCTUnwrap(Bundle.main.url(forResource: "AppShortcuts", withExtension: "strings",
                                                    subdirectory: nil, localization: "de"),
                                    "the compiled German App Shortcuts phrases")
        let table = try XCTUnwrap(NSDictionary(contentsOf: phrases) as? [String: String])
        XCTAssertEqual(table["Copy my ${applicationName} code"], "Meinen ${applicationName}-Code kopieren")
    }

    private func assertFails(_ intent: CopyCodeIntent, with expected: CopyCodeError,
                             file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await intent.perform()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let error as CopyCodeError {
            XCTAssertEqual(error, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
        XCTAssertTrue(clipboard.copied.isEmpty, "nothing is copied when there is no code", file: file, line: line)
    }
}
