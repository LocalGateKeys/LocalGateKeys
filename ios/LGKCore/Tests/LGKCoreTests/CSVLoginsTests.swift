import XCTest
@testable import LGKCore

final class CSVLoginsTests: XCTestCase {
    private let appleHeader = "Title,URL,Username,Password,Notes,OTPAuth"

    private func login(_ c: ImportCandidate) -> LoginFields? {
        if case .login(let l) = c.kind { return l }
        return nil
    }

    func testAppleHeaderMapsAllColumns() throws {
        let text = appleHeader + "\n" +
            "\"Bank\",\"https://bank.example\",\"a@b.c\",\"p,w\",\"line1\nline2\",\"otpauth://totp/x?secret=JBSWY3DP\"\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].title, "Bank")
        XCTAssertEqual(login(out[0]), LoginFields(
            url: "https://bank.example", username: "a@b.c", password: "p,w",
            notes: "line1\nline2", otpauth: "otpauth://totp/x?secret=JBSWY3DP"))
    }

    func testChromeHeader() throws {
        let text = "name,url,username,password,note\nSite,https://s.example,bob,pw,hello\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(out.count, 1)
        XCTAssertEqual(out[0].title, "Site")
        XCTAssertEqual(login(out[0]), LoginFields(
            url: "https://s.example", username: "bob", password: "pw", notes: "hello", otpauth: nil))
    }

    func testBOMAndCRLF() throws {
        let text = "\u{FEFF}" + appleHeader + "\r\nA,https://a.example,u,p,,\r\nB,https://b.example,v,q,,\r\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(out.map(\.title), ["A", "B"])
        XCTAssertNil(login(out[0])?.otpauth)
    }

    func testUnterminatedQuoteThrows() {
        XCTAssertThrowsError(try CSV.parse("a,b\n\"c,d\n")) {
            XCTAssertEqual($0 as? CSV.Error, .unterminatedQuote(line: 2))
        }
    }

    func testUnknownHeaderThrows() {
        XCTAssertThrowsError(try CSVLogins.candidates(from: "foo,bar\n1,2\n")) {
            XCTAssertEqual($0 as? CSVLogins.Error, .unknownFormat)
        }
    }

    func testEmptyPasswordRowDropped() throws {
        let text = appleHeader + "\nA,https://a.example,u,,,\nB,,,p,,\nC,,u,p,,\nD,https://d.example,,p,,\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(out.map(\.title), ["C", "D"])
    }

    func testHeaderCaseInsensitive() throws {
        let out = try CSVLogins.candidates(from: "NAME,URL,Username,PASSWORD,Note\nS,https://s.example,u,p,\n")
        XCTAssertEqual(out.count, 1)
    }

    func testReorderedAppleColumns() throws {
        let text = "Password,OTPAuth,Title,Notes,Username,URL\np,,T,n,u,https://t.example\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(out[0].title, "T")
        XCTAssertEqual(login(out[0]), LoginFields(
            url: "https://t.example", username: "u", password: "p", notes: "n", otpauth: nil))
    }

    func testChromeWithExtraColumn() throws {
        let text = "name,url,username,password,note,extra\nS,https://s.example,u,p,n,zzz\n"
        let out = try CSVLogins.candidates(from: text)
        XCTAssertEqual(login(out[0])?.notes, "n")
        XCTAssertEqual(login(out[0])?.password, "p")
    }

    func testChromeWithoutNote() throws {
        let out = try CSVLogins.candidates(from: "name,url,username,password\nS,https://s.example,u,p\n")
        XCTAssertEqual(login(out[0]), LoginFields(
            url: "https://s.example", username: "u", password: "p", notes: "", otpauth: nil))
    }
}
