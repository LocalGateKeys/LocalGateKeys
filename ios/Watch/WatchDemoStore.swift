#if DEBUG
import Foundation
import LGKCore

/// DEBUG builds only: sample codes for screenshots, kept in memory (nothing written to the Keychain).
/// Launch the watch app with `-LGKDemoData YES`.
struct WatchDemoStore: WatchSecretStoring {
    static var requested: Bool { UserDefaults.standard.bool(forKey: "LGKDemoData") }

    func load() -> [WatchCode] {
        [WatchCode(id: "demo-1", title: "github.com", secret: "JBSWY3DPEHPK3PXP"),
         WatchCode(id: "demo-2", title: "proton.me", secret: "GEZDGNBVGY3TQOJQ"),
         WatchCode(id: "demo-3", title: "google.com", secret: "MFRGGZDFMZTWQ2LK"),
         WatchCode(id: "demo-4", title: "Bank", secret: "KRSXG5CTMVRXEZLU")]
    }
    func save(_ codes: [WatchCode]) throws {}
    func removeAll() {}
}
#endif
