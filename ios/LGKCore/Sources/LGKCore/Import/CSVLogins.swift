import Foundation

/// Maps Apple Passwords and Chrome/Edge password CSV exports to login candidates.
public enum CSVLogins {
    public enum Error: Swift.Error, Equatable {
        case unknownFormat
    }

    public static func candidates(from text: String) throws -> [ImportCandidate] {
        let rows = try CSV.parse(text)
        guard let header = rows.first else { throw Error.unknownFormat }
        var index: [String: Int] = [:]
        for (i, cell) in header.enumerated() {
            let name = cell.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if index[name] == nil { index[name] = i }
        }
        func has(_ names: [String]) -> Bool { names.allSatisfy { index[$0] != nil } }

        let titleKey: String, notesKey: String, otpKey: String?
        if has(["title", "url", "username", "password", "notes"]) {
            titleKey = "title"; notesKey = "notes"; otpKey = "otpauth"
        } else if has(["name", "url", "username", "password"]) {
            titleKey = "name"; notesKey = "note"; otpKey = nil
        } else {
            throw Error.unknownFormat
        }
        let iTitle = index[titleKey], iURL = index["url"]
        let iUser = index["username"], iPass = index["password"]
        let iNotes = index[notesKey], iOTP = otpKey.flatMap { index[$0] }

        var out: [ImportCandidate] = []
        for row in rows.dropFirst() {
            func cell(_ i: Int?) -> String {
                guard let i, i < row.count else { return "" }
                return row[i]
            }
            let password = cell(iPass)
            let url = cell(iURL), username = cell(iUser)
            if password.isEmpty || (url.isEmpty && username.isEmpty) { continue }
            let otp = cell(iOTP).isEmpty ? nil : cell(iOTP)
            out.append(ImportCandidate(
                title: cell(iTitle),
                kind: .login(LoginFields(url: url, username: username, password: password,
                                         notes: cell(iNotes), otpauth: otp))))
        }
        return out
    }
}
