import XCTest
import AuthenticationServices
import AppShared
@testable import LocalGateKeys

final class CredentialExchangeImportTests: XCTestCase {
    func testEncodesAppleDataThroughCXF() throws {
        guard #available(iOS 26.4, *) else { throw XCTSkip("These SDK initialisers need iOS 26.4") }
        let der = Data(decodeBase64URL(PasskeyKey.generate().pkcs8B64URL, maxBytes: 1024)!)
        let login = ASImportableItem(
            id: Data([1]), title: "Example Mail",
            scope: ASImportableCredentialScope(urls: [URL(string: "https://mail.example.test/login")!]),
            credentials: [
                .basicAuthentication(.init(
                    userName: ASImportableEditableField(id: nil, fieldType: .string, value: "ada"),
                    password: ASImportableEditableField(id: nil, fieldType: .concealedString, value: "correct horse"))),
                .totp(.init(secret: Data("Hello!\u{DE}\u{AD}\u{BE}\u{EF}".utf8.prefix(10)), period: 30, digits: 6,
                            userName: "ada", algorithm: .sha1, issuer: "Example")),
                .note(.init(content: ASImportableEditableField(id: nil, fieldType: .string, value: "recovery in drawer"))),
            ])
        let passkey = ASImportableItem(
            id: Data([2]), title: "PK Site", scope: nil,
            credentials: [.passkey(.init(credentialID: Data([1, 2, 3, 4, 5, 6, 7, 8]), relyingPartyIdentifier: "pk.example.test",
                                         userName: "bob", userDisplayName: "Bob B", userHandle: Data([10, 11, 12]),
                                         key: der, fido2Extensions: nil))])
        let account = ASImportableAccount(id: Data([9]), userName: "", email: "", collections: [], items: [login, passkey])
        let data = ASExportedCredentialData(accounts: [account], formatVersion: .v1,
                                            exporterRelyingPartyIdentifier: "apple.com", exporterDisplayName: "Passwords",
                                            timestamp: Date(timeIntervalSince1970: 1_700_000_000))


        let r = try CredentialExchangeImport.candidates(from: data)
        XCTAssertEqual(r.unsupported, 0)
        XCTAssertEqual(r.candidates.count, 2)
        guard r.candidates.count == 2 else { return }
        XCTAssertEqual(r.candidates[0].title, "Example Mail")
        guard case .login(let f) = r.candidates[0].kind else { return XCTFail("not a login") }
        XCTAssertEqual(f.url, "https://mail.example.test/login")
        XCTAssertEqual(f.username, "ada")
        XCTAssertEqual(f.password, "correct horse")
        XCTAssertEqual(f.notes, "recovery in drawer")
        XCTAssertNotNil(f.otpauth)
        XCTAssertEqual(r.candidates[1].title, "PK Site")
        guard case .passkey(let p) = r.candidates[1].kind else { return XCTFail("not a passkey") }
        XCTAssertEqual(p.rpID, "pk.example.test")
        XCTAssertEqual(p.userName, "bob")
        XCTAssertEqual(p.userDisplayName, "Bob B")
        XCTAssertEqual(p.credentialID, Data([1, 2, 3, 4, 5, 6, 7, 8]))
        XCTAssertEqual(p.userHandle, Data([10, 11, 12]))
        XCTAssertEqual(p.pkcs8, der)
    }

    func testTokenOnlyFromExchangeActivity() throws {
        guard #available(iOS 26, *) else { throw XCTSkip("Credential Exchange needs iOS 26") }
        let id = UUID()
        let a = NSUserActivity(activityType: ASCredentialExchangeActivity)
        a.userInfo = [ASCredentialImportToken: id]
        XCTAssertEqual(CredentialExchangeImport.token(from: a), id)
        let other = NSUserActivity(activityType: "com.example.other")
        other.userInfo = [ASCredentialImportToken: id]
        XCTAssertNil(CredentialExchangeImport.token(from: other))
        XCTAssertEqual(CredentialExchangeModel.activityType, ASCredentialExchangeActivity)
    }

    private func login(_ n: Int) -> ImportCandidate {
        ImportCandidate(title: "Site \(n)", kind: .login(LoginFields(url: "https://s\(n).example.test", username: "u",
                                                                     password: "p", notes: "", otpauth: nil)))
    }

    @MainActor
    func testRunsOnceAndSurvivesTokenChange() async throws {
        var calls = 0
        var release: CheckedContinuation<Void, Never>?
        let model = CredentialExchangeModel(fetch: { _ in
            calls += 1
            await withCheckedContinuation { release = $0 }
            try Task.checkCancellation()
            return ([self.login(1)], 0)
        })
        let importer = VaultImporter(store: MemoryStore(), isPro: { true }, now: { Date() }, random: SystemRandomSource())
        let first = UUID()
        model.received(token: first)
        let task = try XCTUnwrap(model.start(importer: importer))
        XCTAssertNil(model.start(importer: importer), "a second start while running does nothing")
        while release == nil { await Task.yield() }
        XCTAssertEqual(model.pendingToken, first, "the token is kept until the import finishes")
        let second = UUID()
        model.received(token: second)   // the id flipping mid-run must not cancel it
        release?.resume()
        await task.value
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(model.message, "1 added")
        XCTAssertEqual(model.pendingToken, second, "a token that arrived during the run stays pending")
        XCTAssertFalse(model.isRunning)
    }

    @MainActor
    func testFailureMessages() async throws {
        let importer = VaultImporter(store: MemoryStore(), isPro: { true }, now: { Date() }, random: SystemRandomSource())
        for (error, expected) in [(CredentialExchangeModel.FetchError.exchange, CredentialExchangeModel.exchangeFailedMessage),
                                  (.unreadable, CredentialExchangeModel.unreadableMessage)] {
            let model = CredentialExchangeModel(fetch: { _ in throw error })
            model.received(token: UUID())
            await model.start(importer: importer)?.value
            XCTAssertEqual(model.message, expected)
            XCTAssertNil(model.pendingToken)
        }
        let cancelled = CredentialExchangeModel(fetch: { _ in throw CancellationError() })
        let token = UUID()
        cancelled.received(token: token)
        await cancelled.start(importer: importer)?.value
        XCTAssertNil(cancelled.message, "no failure shown for a cancelled run")
        XCTAssertEqual(cancelled.pendingToken, token, "kept so it can be retried")
    }
}
