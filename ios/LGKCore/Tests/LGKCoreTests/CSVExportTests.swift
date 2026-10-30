import XCTest
@testable import LGKCore

final class CSVExportTests: XCTestCase {
    func testHeaderQuotingAndCRLF() {
        let csv = CSVExport.appleCSV(
            logins: [LoginFields(url: "https://a.example", username: "ada", password: "p\"w", notes: "", otpauth: nil)],
            titles: ["A, Inc"])
        XCTAssertEqual(csv, "Title,URL,Username,Password,Notes,OTPAuth\r\n\"A, Inc\",https://a.example,ada,\"p\"\"w\",,\r\n")
    }

    func testCSVExportRoundTripsThroughCSVLogins() throws {
        let logins = [
            LoginFields(url: "https://a.example", username: "ada", password: "pa,ss", notes: "line 1\nline 2", otpauth: nil),
            LoginFields(url: "https://b.example/login", username: "bob \"b\"", password: "x\r\ny",
                        notes: "", otpauth: "otpauth://totp/B?secret=JBSWY3DPEHPK3PXP"),
        ]
        let titles = ["Alpha, the first", "Bravo"]
        let parsed = try CSVLogins.candidates(from: CSVExport.appleCSV(logins: logins, titles: titles))
        XCTAssertEqual(parsed, zip(titles, logins).map { ImportCandidate(title: $0, kind: .login($1)) })
    }
}
