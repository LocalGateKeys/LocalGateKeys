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

/// The Mac copy of the iPhone handler (ios/SafariSave), unchanged but for the framework it links.
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
        Task {
            // Safari's keys open without Touch ID while the Mac is unlocked (no LAContext). They are in the
            // extension's own Keychain group, its only one (audit 2026-10-24 L-8): nothing else is readable here.
            let service = SafariSaveService(keychain: SafariKeys.extensionVault(), settings: AppSettings.shared,
                                            entitlement: StoreKitEntitlement())
            AutoFillTrace.log("safari handler: request keys=\(request.count) host=\(host: request["origin"])")
            let reply = await service.handle(request)
            AutoFillTrace.log("safari handler: status=\(host: reply["status"] as? String) stored=\((reply["stored"] as? Bool) ?? false) error=\(host: reply["error"] as? String)")
            let response = NSExtensionItem()
            response.userInfo = [SFExtensionMessageKey: reply]
            box.context.completeRequest(returningItems: [response], completionHandler: nil)
        }
    }
}
