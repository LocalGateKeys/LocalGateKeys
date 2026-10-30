import Foundation

/// RFC 4180 CSV reader. Strips a leading BOM; accepts CRLF, LF and lone CR line ends.
public enum CSV {
    public enum Error: Swift.Error, Equatable {
        /// `line` is the 1-based line on which the unclosed quoted field opened.
        case unterminatedQuote(line: Int)
    }

    public static func parse(_ text: String) throws -> [[String]] {
        var scalars = Array(text.unicodeScalars)
        if scalars.first == "\u{FEFF}" { scalars.removeFirst() }

        var rows: [[String]] = []
        var row: [String] = []
        var field = String.UnicodeScalarView()
        var inQuotes = false
        var quoteLine = 1
        var line = 1
        var fieldStarted = false  // distinguishes an empty trailing line from a row of one empty field
        var i = 0

        func endField() {
            row.append(String(field))
            field = String.UnicodeScalarView()
            fieldStarted = false
        }
        func endRow() {
            if fieldStarted || !row.isEmpty { endField(); rows.append(row) }
            row = []
        }

        while i < scalars.count {
            let c = scalars[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < scalars.count, scalars[i + 1] == "\"" {
                        field.append("\""); i += 1
                    } else {
                        inQuotes = false
                    }
                } else {
                    if c == "\n" { line += 1 }
                    field.append(c)
                }
            } else {
                switch c {
                case "\"":
                    inQuotes = true; fieldStarted = true; quoteLine = line
                case ",":
                    endField(); fieldStarted = true
                case "\r", "\n":
                    if c == "\r", i + 1 < scalars.count, scalars[i + 1] == "\n" { i += 1 }
                    endRow(); line += 1
                default:
                    field.append(c); fieldStarted = true
                }
            }
            i += 1
        }
        if inQuotes { throw Error.unterminatedQuote(line: quoteLine) }
        endRow()
        return rows
    }
}
