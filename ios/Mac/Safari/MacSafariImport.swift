import Foundation
import Observation
import LGKCore
import AppSharedMac

/// The Safari inbox import of the Mac app, as on the iPhone (`SafariImportModel`): right after each unlock it
/// creates the Safari keys when missing, publishes the fingerprint index and lists what the Safari extension
/// saved; the window asks with `MacSafariReviewSheet` and only confirmed logins are imported, in one store
/// commit (so the AutoFill identities are republished once, by `PublishingItemStore`). New logins over the
/// free limit stay in the inbox and the Pro sheet opens (`onNeedsPro(.itemLimit)`). Each saved login records
/// one content-free activity event (`item.create` or `item.update` with its id).
@MainActor
@Observable
final class MacSafariImport {
    /// The notice after an import ("2 logins saved from Safari · 1 waiting: upgrade to Pro to import").
    private(set) var notice: String?
    var pending: [SafariPendingSave] { model.pending }

    @ObservationIgnored let model: SafariImportModel
    /// The Safari keys' vault (`SafariKeys.appVault`): the two keys only, no Touch ID.
    @ObservationIgnored let keychain: any KeychainVault

    init(keychain: any KeychainVault, clock: any UnixClock = SystemClock(),
         directory: @escaping @Sendable () throws -> URL = { try SafariSaveFiles.directory() }) {
        self.keychain = keychain
        let sink = NoticeSink()
        model = SafariImportModel(clock: clock, background: MacActivityTasks(), directory: directory,
                                  show: { sink.show?($0) })
        sink.show = { [weak self] in self?.notice = $0 }
    }

    /// Right after unlock (the window's task): keys, index, then `pending` for the sheet.
    func afterUnlock(store: any ItemStore, pro: ProModel, isUnlocked: @MainActor () -> Bool) async {
        await model.afterUnlock(store: store, keychain: keychain, pro: pro, isUnlocked: isUnlocked)
    }

    /// The person answered the sheet. Imports the approved entries (the others are deleted), records one
    /// activity event per saved login, and asks for Pro when new logins wait. nil when nothing ran.
    @discardableResult
    func confirm(_ approved: Set<String>, store: any ItemStore, isPro: Bool, activity: ActivityRecorder?,
                 onNeedsPro: (ProReason) -> Void) -> SafariImportResult? {
        let before = (try? store.load())?.records ?? [:]
        guard let result = model.confirm(approved, store: store, keychain: keychain, isPro: isPro) else { return nil }
        if result.saved > 0, let activity, let after = try? store.load().records {
            for id in after.keys.sorted() where before[id] != after[id] {
                activity.record(before[id] == nil ? .itemCreate : .itemUpdate, itemID: id)
            }
        }
        if result.waiting > 0 { onNeedsPro(.itemLimit) }
        return result
    }

    /// "Decide later": everything stays in the inbox for the next unlock.
    func later() { model.later() }

    func clearNotice() { notice = nil }

    /// The vault locked: the next unlock asks again.
    func locked() { model.locked(); notice = nil }
}

/// Carries the notice from `SafariImportModel` back to the Mac model that owns it.
@MainActor
private final class NoticeSink {
    var show: ((String) -> Void)?
}
