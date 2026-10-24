/// Conflict-copy label/title suffix (vectors README "Suffix and truncation"). Lengths are code points.
public enum ConflictSuffix {
    public static let suffix = " (sync conflict)"
    /// Entry `label` and typed-item `title` limit.
    public static let limit = 512

    public static func apply(_ text: String, limit: Int) -> String {
        if text.unicodeScalars.reversed().starts(with: suffix.unicodeScalars.reversed()) {
            return text
        }
        let keep = max(0, limit - suffix.unicodeScalars.count)
        return String(String.UnicodeScalarView(text.unicodeScalars.prefix(keep))) + suffix
    }
}
