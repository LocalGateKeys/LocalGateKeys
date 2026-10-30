import Foundation

/// Firefox logins CSV; Windows reads it with the browser CSV loader, which picks the layout from the header.
public enum FirefoxCSV: Importer {
    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        try BrowserCSV.load(data)
    }
}
