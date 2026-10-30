/// Where the detail screen copies to: `SecretClipboard` on the iPhone, `MacClipboard` on the Mac.
@MainActor
protocol SecretCopying: AnyObject {
    func copy(_ text: String)
}
