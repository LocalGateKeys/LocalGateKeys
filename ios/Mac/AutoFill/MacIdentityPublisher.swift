import Foundation
import AppSharedMac

/// Publishes the vault's AutoFill identities (passwords, passkeys and, on macOS 15 and later, one-time codes)
/// with the iPhone's `IdentityStoreSync` rules: at unlock, after every successful store commit and when an
/// AutoFill setting changes. Removed when "Show logins in AutoFill suggestions" is off or the vault is replaced;
/// nothing happens at lock. One update runs at a time, in the order they were asked for.
@MainActor
final class MacIdentityPublisher {
    private let sync: IdentityStoreSync
    private var tail: Task<Void, Never>?

    init(store: any CredentialIdentityStoring, settings: AppSettings,
         matcher: URLMatcher = AutoFillMatcher.bundled().matcher) {
        let codes: Bool = if #available(macOS 15.0, *) { true } else { false }
        sync = IdentityStoreSync(identityStore: store, matcher: matcher, settings: settings, oneTimeCodes: codes)
    }

    /// Replaces the published identities with `snapshot`'s (or removes them, per the settings), after the
    /// updates queued before it.
    func publish(snapshot: StoreSnapshot) async {
        enqueue(snapshot: snapshot)
        await settled()
    }

    /// Queues `publish` without waiting (commit hooks).
    func enqueue(snapshot: StoreSnapshot) {
        let sync = sync
        chain { await sync.refresh(snapshot) }
    }

    /// Removes every identity this app published, after the updates queued before it.
    func removeAll() async {
        enqueueRemoveAll()
        await settled()
    }

    /// Queues `removeAll` without waiting (a setting turned off while locked).
    func enqueueRemoveAll() {
        let sync = sync
        chain { await sync.removeAll() }
    }

    /// Waits for the updates queued so far.
    func settled() async { await tail?.value }

    private func chain(_ work: @escaping @Sendable () async -> Void) {
        let previous = tail
        tail = Task { await previous?.value; await work() }
    }
}

/// The unlocked store as the app sees it: every successful `commit` (editor, favourites, trash, login extras,
/// collections, the palette, imports) runs `onCommit`, the one place the AutoFill identities are republished.
final class PublishingItemStore: ItemStore, @unchecked Sendable {
    let base: any ItemStore
    private let onCommit: @Sendable (_ fromSync: Bool) -> Void

    /// `onCommit` gets `fromSync: true` only for commits made through `commit(_:fromSync:)` by sync.
    init(base: any ItemStore, onCommit: @escaping @Sendable (_ fromSync: Bool) -> Void) {
        self.base = base; self.onCommit = onCommit
    }

    func load() throws -> StoreSnapshot { try base.load() }

    /// A local commit (editor, trash, import...): counts as an edit.
    func commit(_ change: StoreChange) throws { try commit(change, fromSync: false) }

    /// `fromSync: true` for a merge or pairing written by sync (`SyncSourceStore`), never an edit.
    func commit(_ change: StoreChange, fromSync: Bool) throws {
        try base.commit(change)
        onCommit(fromSync)
    }
}
