import XCTest
@testable import LGKCore

/// Pins the text-format importers to the Windows ones: `tests/vectors/import` is written by
/// `scripts/gen_mac_backup_vectors.py`, which runs `localvault.importers` over every fixture.
final class ImporterVectorTests: XCTestCase {
    private static let repo: URL = Vectors.root.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    private static let vectors = repo.appendingPathComponent("tests/vectors/import", isDirectory: true)

    private func json(_ url: URL) throws -> Any { try JSONSerialization.jsonObject(with: Data(contentsOf: url)) }

    private func cases() throws -> [(URL, [String: Any])] {
        var out: [(URL, [String: Any])] = []
        let dirs = try FileManager.default.contentsOfDirectory(at: Self.vectors, includingPropertiesForKeys: [.isDirectoryKey])
        for dir in dirs.sorted(by: { $0.path < $1.path }) where dir.hasDirectoryPath && dir.lastPathComponent != "_inputs" {
            for file in try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
                .sorted(by: { $0.path < $1.path }) where file.lastPathComponent.hasSuffix(".expected.json") {
                out.append((file, try json(file) as! [String: Any]))
            }
        }
        return out
    }

    /// The candidate as the generator writes a Windows `ImportedRecord`.
    private func normalised(_ c: ImportCandidate) -> [String: Any] {
        var kind = "", username = "", password = "", notes = "", totp = ""
        var identity: [String: String] = [:], card: [String: String] = [:]
        switch c.kind {
        case .login(let f): kind = "login"; username = f.username; password = f.password; notes = f.notes
        case .note(let f): kind = "note"; notes = f.notes
        case .card(let f): kind = "card"; notes = f.notes; card = f.values
        case .identity(let f): kind = "identity"; notes = f.notes; identity = f.values
        case .passkey: kind = "passkey"
        }
        totp = c.totp ?? ""  // any kind: 1PUX and Proton Pass keep two-factor keys on notes, cards and identities
        let none = NSNull()
        return [
            "kind": kind, "title": c.title, "username": username, "password": password, "urls": c.urls, "notes": notes,
            "totp_uri": totp, "folder": c.folder, "favorite": c.favourite,
            "custom_fields": c.customFields.map { ["name": $0.name, "value": $0.value, "hidden": $0.hidden] as [String: Any] },
            "created": c.created.map { NSNumber(value: $0) } ?? none, "modified": c.modified.map { NSNumber(value: $0) } ?? none,
            "tags": c.tags, "identity": identity, "card": card,
            "source_row": c.sourceRow.map { NSNumber(value: $0) } ?? none,
        ]
    }

    private func mapping(_ names: [String: String], header: [String]) -> GenericCSVMapping {
        func index(_ t: String) -> Int? { names[t].flatMap { header.firstIndex(of: $0) } }
        return GenericCSVMapping(title: index("title"), url: index("url"), username: index("username"),
                                 password: index("password"), notes: index("notes"), totp: index("totp"))
    }

    func testEachFormatMatchesPython() throws {
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 40)
        var checkedRecords = 0
        for (file, v) in all {
            let name = file.lastPathComponent
            let input = try Data(contentsOf: Self.repo.appendingPathComponent(v["input"] as! String))
            guard let format = ImportFormat(rawValue: v["format"] as! String) else { XCTFail("\(name): format"); continue }
            var options = ImportOptions(password: v["password"] as? String)
            if let names = v["mapping"] as? [String: String] {
                options.mapping = mapping(names, header: try GenericCSV.header(from: input))
            }
            if let error = v["error"] as? [String: String] {
                XCTAssertThrowsError(try ImportSource.candidates(from: input, format: format, options: options), name) { e in
                    guard let e = e as? ImportError else { return XCTFail("\(name): \(e)") }
                    if error["type"] == "password_required" { XCTAssertEqual(e, .needsPassword, name) }
                    else if error["type"] == "wrong_password" {
                        // The Mac adds key-file guidance to the KeePass wording.
                        XCTAssertTrue(e.isWrongPassword, name)
                        XCTAssertTrue(e.message.hasPrefix(error["message"]!), "\(name): \(e.message)")
                    } else { XCTAssertEqual(e.message, error["message"], name) }
                }
                continue
            }
            let expected = v["result"] as! [String: Any]
            let result: ImportResult
            do { result = try ImportSource.candidates(from: input, format: format, options: options) } catch {
                XCTFail("\(name): \(error)"); continue
            }
            XCTAssertEqual(result.skipped.map(\.message), expected["diagnostics"] as! [String], name)
            let records = expected["records"] as! [[String: Any]]
            XCTAssertEqual(result.candidates.count, records.count, name)
            for (i, (c, want)) in zip(result.candidates, records).enumerated() {
                let got = normalised(c)
                for key in want.keys.sorted() {
                    let a = got[key] as AnyObject, b = want[key] as AnyObject
                    XCTAssertTrue(a.isEqual(b), "\(name) record \(i) \(key): \(a) != \(b)")
                }
                checkedRecords += 1
            }
        }
        XCTAssertGreaterThan(checkedRecords, 100)
    }

    func testDetectMatchesPython() throws {
        let doc = try json(Self.vectors.appendingPathComponent("detect.json")) as! [[String: Any]]
        XCTAssertGreaterThan(doc.count, 50)
        for v in doc {
            let path = v["input"] as! String
            let data = try Data(contentsOf: Self.repo.appendingPathComponent(path))
            let got = ImportDetect.detect(data: data, filename: (path as NSString).lastPathComponent)
            XCTAssertEqual(got?.rawValue, v["format"] as? String, path)
        }
    }

    func testGenericMappingSuggestion() throws {
        let doc = try json(Self.vectors.appendingPathComponent("generic_mapping.json")) as! [[String: Any]]
        XCTAssertFalse(doc.isEmpty)
        for v in doc {
            let header = v["header"] as! [String]
            let want = v["mapping"] as! [String: String]
            let got = GenericCSV.suggestMapping(header: header)
            XCTAssertEqual(got, mapping(want, header: header), v["input"] as! String)
        }
        let m = GenericCSV.suggestMapping(header: ["Label", "Address", "Email", "Pwd", "Comments", "TOTP Secret"])
        XCTAssertEqual(m, GenericCSVMapping(title: 0, url: 1, username: 2, password: 3, notes: 4, totp: 5))
    }

    func testRowLimitRefused() throws {
        let rows = (0...ImportSource.maxRecords).map { "n\($0),https://h\($0).example.com,u,p\n" }.joined()
        let data = Data(("name,url,username,password\n" + rows).utf8)
        XCTAssertThrowsError(try ImportSource.candidates(from: data, format: .chrome)) {
            XCTAssertEqual($0 as? ImportError, .tooManyRows)
            XCTAssertEqual(($0 as? ImportError)?.message, "At most 5,000 records per import")
        }
        let ok = (1..<ImportSource.maxRecords).map { "n\($0),https://h\($0).example.com,u,p\n" }.joined()
        XCTAssertEqual(try ImportSource.candidates(from: Data(("name,url,username,password\n" + ok).utf8), format: .chrome)
            .candidates.count, ImportSource.maxRecords - 1)
        // The CSV reader stops at 20,000 rows whatever they hold.
        let blank = String(repeating: "x,,,\n", count: ImportSource.maxCSVRows + 1)
        XCTAssertThrowsError(try ImportSource.candidates(from: Data(("name,url,username,password\n" + blank).utf8), format: .chrome)) {
            XCTAssertEqual(($0 as? ImportError)?.message, "At most 20,000 rows per CSV import")
        }
    }

    func testOversizeRefused() throws {
        var data = Data("name,url,username,password\n".utf8)
        data.append(Data(repeating: 0x61, count: ImportSource.maxSourceBytes + 1 - data.count))
        for format in [ImportFormat.chrome, .bitwarden, .lastPass, .keePassXML, .protonPass, .dashlane, .generic] {
            XCTAssertThrowsError(try ImportSource.candidates(from: data, format: format), format.rawValue) {
                XCTAssertEqual($0 as? ImportError, .tooLarge, format.rawValue)
                XCTAssertEqual(($0 as? ImportError)?.message, "Import source exceeds 8 MiB")
            }
        }
        // At the limit the size check passes; this one-field body then trips Python's 131,072-character field limit.
        XCTAssertThrowsError(try ImportSource.candidates(from: data.prefix(ImportSource.maxSourceBytes), format: .chrome)) {
            XCTAssertEqual($0 as? ImportError, .malformed("CSV is malformed"))
        }
        XCTAssertNil(ImportDetect.detect(data: Data(count: ImportSource.maxArchiveBytes + 1), filename: "big.csv"))
    }

    /// Fields are capped by the reader (50 fields, 100-character names, 4,096-character values); URLs are all kept
    /// (the review step applies the vault's 20-URL limit, as on Windows).
    func testURLAndFieldLimitsTruncateLikePython() throws {
        let vector = try json(Self.vectors.appendingPathComponent("lastPass/lastpass_notes.csv.expected.json")) as! [String: Any]
        let input = try Data(contentsOf: Self.repo.appendingPathComponent(vector["input"] as! String))
        let server = try ImportSource.candidates(from: input, format: .lastPass).candidates.first { $0.title == "Server note" }!
        XCTAssertEqual(server.customFields.count, 50)
        let records = (vector["result"] as! [String: Any])["records"] as! [[String: Any]]
        let want = records.first { $0["title"] as? String == "Server note" }!["custom_fields"] as! [[String: Any]]
        XCTAssertEqual(server.customFields.map(\.name), want.map { $0["name"] as! String })

        var r = ImportRecord()
        r.addField(String(repeating: "n", count: 150), String(repeating: "é", count: 5000))
        XCTAssertEqual(Py.len(r.fields[0].name), 100)
        XCTAssertEqual(Py.len(r.fields[0].value), 4096)
        for i in 0..<60 { r.addField("f\(i)", "v") }
        XCTAssertEqual(r.fields.count, 50)
        r.addField("", "v"); r.addField("x", ""); r.addField("y", nil as String?)
        XCTAssertEqual(r.fields.count, 50)

        let bw = try json(Self.vectors.appendingPathComponent("bitwarden/bitwarden_types.json.expected.json")) as! [String: Any]
        let bwInput = try Data(contentsOf: Self.repo.appendingPathComponent(bw["input"] as! String))
        let many = try ImportSource.candidates(from: bwInput, format: .bitwarden).candidates[0]
        XCTAssertEqual(many.urls.count, 25)
        guard case .login(let f) = many.kind else { return XCTFail("not a login") }
        XCTAssertEqual(f.url, "https://u0.example.com")
    }

    func testDiagnosticsCappedLikeWindows() {
        let list = (1...53).map { ImportSkip(message: "m\($0)") }
        let capped = ImportSource.capDiagnostics(list)
        XCTAssertEqual(capped.count, 51)
        XCTAssertEqual(capped.last?.message, "...and 3 more messages.")
        XCTAssertEqual(ImportSource.capDiagnostics(Array(list.prefix(51))).last?.message, "...and 1 more message.")
    }

    func testArchiveAndEncryptedFormatsHaveReaders() {
        for format in ImportFormat.allCases { XCTAssertNotNil(format.importer, format.rawValue) }
        XCTAssertThrowsError(try ImportSource.candidates(from: Data("{}".utf8), format: .onePassword1PUX)) {
            XCTAssertEqual(($0 as? ImportError)?.message, "export.data has no 'accounts' list")
        }
        let protected = Data(#"{"encrypted": true, "passwordProtected": true, "data": "2.x"}"#.utf8)
        XCTAssertThrowsError(try ImportSource.candidates(from: protected, format: .bitwarden)) {
            XCTAssertEqual($0 as? ImportError, .needsPassword)
        }
    }
}
