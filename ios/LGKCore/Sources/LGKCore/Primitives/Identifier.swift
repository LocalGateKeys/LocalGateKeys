public enum Identifier {
    private static let reserved: Set<String> =
        ["CON", "PRN", "AUX", "NUL"].reduce(into: Set<String>()) { $0.insert($1) }
        .union((0...9).map { "COM\($0)" }).union((0...9).map { "LPT\($0)" })

    /// Format-1 identifier: ASCII `[A-Za-z0-9._:-]`, 1...128 characters.
    public static func isValid(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard (1...128).contains(u.count) else { return false }
        return u.allSatisfy { c in
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
                || c == 0x2E || c == 0x5F || c == 0x3A || c == 0x2D
        }
    }

    /// A valid id that is also a safe Windows/macOS file name stem.
    public static func isSafeDeviceFile(_ s: String) -> Bool {
        guard isValid(s) else { return false }
        if s.contains(":") || s.hasPrefix(".") || s.hasSuffix(".") || s.hasSuffix(" ") { return false }
        let stem = s.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false)[0]
        return !reserved.contains(stem.uppercased())
    }
}
