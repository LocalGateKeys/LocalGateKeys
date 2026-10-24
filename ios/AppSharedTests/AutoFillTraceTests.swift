#if DEBUG
import XCTest
@testable import AppShared

final class AutoFillTraceTests: XCTestCase {
    func tempDir() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("trace-\(UUID().uuidString)", isDirectory: true)
    }

    func test_appends_timestamped_lines_and_creates_the_folder() throws {
        let dir = tempDir().appendingPathComponent("Diagnostics", isDirectory: true)
        let w = AutoFillTraceWriter(directory: dir, now: { Date(timeIntervalSince1970: 0) })
        w.append("one"); w.append("two")
        let lines = w.read().split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
        XCTAssertTrue(lines[0].hasPrefix("1970-01-01T00:00:00.000Z "))
        XCTAssertTrue(lines[0].hasSuffix(" one")); XCTAssertTrue(lines[1].hasSuffix(" two"))
        XCTAssertEqual(w.fileURL?.lastPathComponent, "autofill-trace.log")
    }

    func test_caps_and_rotates_keeping_one_older_generation() throws {
        let w = AutoFillTraceWriter(directory: tempDir(), maxBytes: 1000)
        for i in 0..<200 { w.append("line \(i) " + String(repeating: "x", count: 40)) }
        let fm = FileManager.default
        let cur = try XCTUnwrap(fm.attributesOfItem(atPath: w.fileURL!.path)[.size] as? NSNumber).intValue
        let old = try XCTUnwrap(fm.attributesOfItem(atPath: w.rotatedURL!.path)[.size] as? NSNumber).intValue
        XCTAssertLessThanOrEqual(cur, 1000); XCTAssertLessThanOrEqual(old, 1000)
        XCTAssertGreaterThan(old, 0)
        let text = w.read()
        XCTAssertTrue(text.contains("line 199 "))   // newest kept
        XCTAssertFalse(text.contains("line 0 "))    // oldest dropped
        // Older generation first, newest last.
        XCTAssertTrue(text.split(separator: "\n").last!.contains("line 199 "))
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: w.directory!.path).sorted(),
                       ["autofill-trace.1.log", "autofill-trace.log"])
    }

    func test_default_cap_is_about_200_KB_on_disk() {
        XCTAssertEqual(AutoFillTraceWriter(directory: nil).maxBytes * 2, 200 * 1024)
    }

    func test_clear_removes_both_files() {
        let w = AutoFillTraceWriter(directory: tempDir(), maxBytes: 100)
        for _ in 0..<10 { w.append(String(repeating: "y", count: 30)) }
        w.clear()
        XCTAssertEqual(w.read(), "")
    }

    func test_no_container_is_os_log_only() {
        let w = AutoFillTraceWriter(directory: nil)
        w.append("x")
        XCTAssertNil(w.fileURL); XCTAssertEqual(w.read(), "")
    }

    // MARK: redaction

    func test_record_id_keeps_only_last_6() {
        let id = "0f3c2a9b-7d41-4e55-9a10-c0ffee123456"
        let m: TraceMessage = "id=\(rid: id)"
        XCTAssertEqual(m.text, "id=…123456(len 36)")
        XCTAssertFalse(m.text.contains("0f3c2a"))
        XCTAssertEqual(TraceRedact.recordID(nil), "nil")
        XCTAssertEqual(TraceRedact.recordID(""), "<empty>")
        XCTAssertEqual(TraceRedact.recordID("abc"), "…abc(len 3)")
    }

    func test_domain_keeps_only_the_host() {
        XCTAssertEqual(TraceRedact.host("https://user:pw@Accounts.Example.com:8443/login?email=a@b.c#x"), "accounts.example.com")
        XCTAssertEqual(TraceRedact.host("example.com"), "example.com")
        XCTAssertEqual(TraceRedact.host("https://example.com/"), "example.com")
        XCTAssertEqual(TraceRedact.host(nil), "nil")
        let m: TraceMessage = "s=\(hosts: ["https://a.example/path?token=1", "b.example"])"
        XCTAssertEqual(m.text, "s=[a.example,b.example]")
        XCTAssertFalse(m.text.contains("token"))
    }

    func test_error_is_type_domain_and_code_only() {
        let e = NSError(domain: "com.apple.LocalAuthentication", code: -1004,
                        userInfo: [NSLocalizedDescriptionKey: "secret user name decave2026@gmail.com"])
        let m: TraceMessage = "e=\(error: e)"
        XCTAssertEqual(m.text, "e=NSError(com.apple.LocalAuthentication -1004)")
        XCTAssertFalse(m.text.contains("decave"))
    }

    func test_numbers_bools_and_fixed_names() {
        let m: TraceMessage = "\(name: "step") n=\(42) ok=\(true) t=\(type: Int.self)"
        XCTAssertEqual(m.text, "step n=42 ok=true t=Int")
    }
}
#endif
