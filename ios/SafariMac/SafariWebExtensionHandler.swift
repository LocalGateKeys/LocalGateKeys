import AppKit
import Foundation
import SafariServices
import StoreKit
import AppSharedMac

/// The `pro_unlimited` entitlement as StoreKit holds it on the device, the same check as the AutoFill
/// extension's. `Transaction.currentEntitlements` is local (works offline, in an extension) and never shows
/// an Apple Account sign-in: no products are loaded and `AppStore.sync()` is never called here.
struct StoreKitEntitlement: SafariProEntitlement {
    func isEntitled() async -> Bool {
        for await result in Transaction.currentEntitlements {
            if case .verified(let t) = result, t.productID == "pro_unlimited", t.revocationDate == nil { return true }
        }
        return false
    }
}

/// The Mac copy of the iPhone handler (ios/SafariSave), but for the framework it links and the `agent_*` actions
/// (an AI agent's approved sign-in, answered by the app over fill.sock: `AgentFillClient` below).
/// Native messages from the Safari extension's background page
/// (`sendNativeMessage("app.localgatekeys.app", {action, origin, username, password[, status]})`).
/// Each one is answered by `SafariSaveService.handle`: classify a captured login, or save it into the
/// sealed inbox the app imports at its next unlock. The extension never reads the vault, never syncs and
/// never opens a network connection. Requests carry passwords: nothing here is ever logged.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    /// `NSExtensionContext` is not Sendable; the box carries it into the task that answers the request,
    /// which is the only code that touches it afterwards.
    private struct ContextBox: @unchecked Sendable { let context: NSExtensionContext }

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        // SFExtensionMessageKey on iOS 15 and later; the literal "message" is the older key (same value
        // today, kept in case the constant ever differs).
        let message = item?.userInfo?[SFExtensionMessageKey] ?? item?.userInfo?["message"]
        // Every request value is a String; keeping only Strings makes the request Sendable.
        let request: [String: String] = (message as? [String: Any])?.compactMapValues { $0 as? String } ?? [:]
        let box = ContextBox(context: context)
        if request["action"] == "open_app_supported" {
            // Whether the popup shows "Open LocalGateKeys": true when this extension sits inside the app it would
            // open (the iPhone's service answers `unsupported`, so the button stays hidden there).
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: ["supported": ContainingApp.url() != nil]]
            box.context.completeRequest(returningItems: [response], completionHandler: nil)
            return
        }
        if request["action"] == "open_app" {
            // The toolbar popup's "Open LocalGateKeys": launch (or bring forward) the app this extension ships in.
            // Nothing is read or sent; the reply is only whether Launch Services accepted it.
            ContainingApp.open { opened in
                let response = NSExtensionItem()
                response.userInfo = [SFExtensionMessageKey: ["opened": opened]]
                box.context.completeRequest(returningItems: [response], completionHandler: nil)
            }
            return
        }
        if let action = request["action"], action.hasPrefix("agent_") {
            // An AI agent's sign-in the user approved in the app (Settings > Developer). The app answers over
            // fill.sock in the Safari app group and checks that this extension is the peer; nothing is logged.
            Task.detached {
                let reply = AgentFillClient.ask(request)
                let response = NSExtensionItem()
                response.userInfo = [SFExtensionMessageKey: reply]
                box.context.completeRequest(returningItems: [response], completionHandler: nil)
            }
            return
        }
        Task {
            // Safari's keys open without Touch ID while the Mac is unlocked (no LAContext). They are in the
            // extension's own Keychain group, its only one (audit 2026-10-24 L-8): nothing else is readable here.
            // Its files are in the Safari app group, the only one it holds (audit 2026-11-10): no vault, no settings.
            let service = SafariSaveService(keychain: SafariKeys.extensionVault(), entitlement: StoreKitEntitlement())
            AutoFillTrace.log("safari handler: request keys=\(request.count) host=\(host: request["origin"])")
            let reply = await service.handle(request)
            AutoFillTrace.log("safari handler: status=\(host: reply["status"] as? String) stored=\((reply["stored"] as? Bool) ?? false) error=\(host: reply["error"] as? String)")
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: reply]
            box.context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }
}

/// The app this extension is embedded in: `LocalGateKeys.app/Contents/PlugIns/SafariMac.appex` -> `LocalGateKeys.app`.
/// Only that exact bundle is opened (never one looked up by identifier, which could be another copy), and only when
/// this extension's identifier is the app's plus a suffix, as Xcode requires of an embedded extension.
enum ContainingApp {
    static func url(extensionBundle: Bundle = .main) -> URL? {
        let appex = extensionBundle.bundleURL.standardizedFileURL
        let plugIns = appex.deletingLastPathComponent()
        let contents = plugIns.deletingLastPathComponent()
        let app = contents.deletingLastPathComponent()
        guard appex.pathExtension == "appex", plugIns.lastPathComponent == "PlugIns", contents.lastPathComponent == "Contents",
              app.pathExtension == "app", let own = extensionBundle.bundleIdentifier,
              let appID = Bundle(url: app)?.bundleIdentifier, own.hasPrefix(appID + ".") else { return nil }
        return app
    }

    static func open(_ done: @escaping @Sendable (Bool) -> Void) {
        guard let app = url() else { done(false); return }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        NSWorkspace.shared.openApplication(at: app, configuration: configuration) { running, error in
            done(error == nil && running != nil)
        }
    }
}

/// The extension's side of `fill.sock` (Mac app: `MacAgentFill`): one JSON line out, one JSON line back. The request
/// carries only `action`, `url`, and for a release the app's one-use token and the picked login's id; the app takes
/// the page's origin from `url` again. Any failure answers `not_found`, so the field icon fills nothing.
enum AgentFillClient {
    static let maxReply = 64 * 1024
    static let allowed: Set<String> = ["action", "url", "grant", "entry_id"]

    static func ask(_ request: [String: String]) -> [String: Any] {
        let notFound: [String: Any] = ["ok": false, "error": "not_found"]
        guard let path = AppGroup.safariContainerURL?.appendingPathComponent("fill.sock", isDirectory: false).path,
              path.utf8.count < 104,
              let body = try? JSONSerialization.data(withJSONObject: request.filter { allowed.contains($0.key) }, options: [.sortedKeys, .withoutEscapingSlashes])
        else { return notFound }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return notFound }
        defer { close(fd) }
        var on: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        // The background page gives up after 15 s; the app answers within a few seconds.
        var timeout = timeval(tv_sec: 12, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            for (i, byte) in bytes.enumerated() where i < raw.count - 1 { raw[i] = byte }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        // The app is not running, or AI agents are off in it.
        guard connected == 0 else { return notFound }
        let line = [UInt8](body) + [0x0A]
        var sent = 0
        while sent < line.count {
            let n = line.withUnsafeBytes { write(fd, $0.baseAddress! + sent, line.count - sent) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { return notFound }
            sent += n
        }
        var reply: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress!, $0.count) }
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { return notFound }
            if n == 0 { break }
            if let newline = chunk[0..<n].firstIndex(of: 0x0A) { reply += chunk[0..<newline]; break }
            reply += chunk[0..<n]
            if reply.count > maxReply { return notFound }
        }
        guard let object = try? JSONSerialization.jsonObject(with: Data(reply)), let dict = object as? [String: Any] else { return notFound }
        return dict
    }
}
