/// Where the detail screen copies to: `SecretClipboard` on the iPhone, `MacClipboard` on the Mac.
@MainActor
protocol SecretCopying: AnyObject {
    func copy(_ text: String)
    /// A copy cleared after at most `seconds`, or the user's shorter setting (copy once, feature pack §4.1).
    func copy(_ text: String, clearAfterAtMost seconds: Int64)
}

extension SecretCopying {
    /// Conformers with no expiry of their own copy as usual.
    func copy(_ text: String, clearAfterAtMost seconds: Int64) { copy(text) }
}
