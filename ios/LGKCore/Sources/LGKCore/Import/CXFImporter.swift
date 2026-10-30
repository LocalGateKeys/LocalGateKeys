import Foundation

/// Credential Exchange (CXF v1.0) `Account` JSON through the common `Importer` interface (wraps `CXFImport`).
public enum CXFImporter: Importer {
    public static func candidates(from data: Data, options: ImportOptions) throws -> ImportResult {
        let source = try ImportText.bounded(data)
        let parsed: (candidates: [ImportCandidate], unsupported: Int)
        do { parsed = try CXFImport.candidates(fromAccountJSON: source) } catch {
            throw ImportError.malformed(String(localized: "The file is not a Credential Exchange account export", bundle: .module))
        }
        try ImportRules.checkCount(parsed.candidates.count)
        let skipped = parsed.unsupported > 0
            ? [ImportSkip(message: String(localized: "\(parsed.unsupported) items of an unsupported type were not imported.", bundle: .module))]
            : []
        return ImportResult(candidates: parsed.candidates, skipped: skipped)
    }
}
