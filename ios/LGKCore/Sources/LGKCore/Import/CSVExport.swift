import Foundation

/// Writes logins in the Apple Passwords CSV layout (the format `CSVLogins` reads back).
public enum CSVExport {
    public static let header = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]

    /// RFC 4180: a field holding a comma, quote, CR or LF is quoted, quotes doubled; CRLF after every row.
    /// `titles[i]` is the title of `logins[i]` (missing titles are empty).
    public static func appleCSV(logins: [LoginFields], titles: [String]) -> String {
        var out = row(header)
        for (i, l) in logins.enumerated() {
            out += row([i < titles.count ? titles[i] : "", l.url, l.username, l.password, l.notes, l.otpauth ?? ""])
        }
        return out
    }

    private static func row(_ fields: [String]) -> String {
        fields.map(field).joined(separator: ",") + "\r\n"
    }

    private static func field(_ s: String) -> String {
        let needsQuotes = s.unicodeScalars.contains { $0 == "," || $0 == "\"" || $0 == "\r" || $0 == "\n" }
        guard needsQuotes else { return s }
        return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}
