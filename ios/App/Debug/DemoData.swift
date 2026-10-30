#if DEBUG
import Foundation
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// DEBUG builds only: fake items for looking at the UI with a full vault. Launch with `-LGKDemoData YES`
/// or use Settings › Developer › Load demo data. Records go through `Normalise` and `Wrapper` like the
/// editor's, are never marked as synced, and skip the free-plan limit. Seeding twice adds nothing.
enum DemoData {
    static let launchArgument = "LGKDemoData"
    static var requestedAtLaunch: Bool { UserDefaults.standard.bool(forKey: launchArgument) }

    private static func id(_ n: Int) -> String { String(format: "de000000-0000-4000-8000-%012d", n) }

    private static func web(_ n: Int, _ origin: String, _ user: String, totp: String? = nil, favorite: Bool = false,
                            password: String? = nil) -> (Namespace, JSONValue) {
        var r: [String: JSONValue] = ["id": .string(id(n)), "kind": .string("web"), "label": .string(origin),
                                      "username": .string(user), "password": .string(password ?? "demo-Pass-\(n)-orbit"),
                                      "scope": .object(["origin": .string("https://\(origin)")]),
                                      "favorite": .bool(favorite), "tags": .array([])]
        if let totp {
            r["totp"] = .object(["secret": .string(totp), "algorithm": .string("SHA1"), "digits": .int(6), "period": .int(30)])
        }
        return (.entry, .object(r))
    }

    private static func item(_ n: Int, _ kind: String, _ title: String, _ payload: [String: JSONValue]) -> (Namespace, JSONValue) {
        (.item, .object(["id": .string(id(n)), "kind": .string(kind), "title": .string(title), "favorite": .bool(false),
                         "tags": .array([]), "payload": .object(payload)]))
    }

    static let records: [(Namespace, JSONValue)] = [
        web(1, "github.com", "alex@example.com", totp: "JBSWY3DPEHPK3PXP", favorite: true),
        web(2, "proton.me", "alex.demo", totp: "GEZDGNBVGY3TQOJQ"),
        web(3, "bank.example", "alex.p"),
        web(4, "google.com", "alex.demo@example.com", totp: "MFRGGZDFMZTWQ2LK"),
        web(5, "amazon.com", "alex@example.com", password: "demo-Shared-orbit-77"),
        web(6, "netflix.com", "family@example.com", password: "netflix1"),
        web(7, "dropbox.com", "alex@example.com", password: "demo-Shared-orbit-77"),
        web(8, "github.com", "alex-work@example.com"),
        item(9, "card", "Visa", ["brand": .string("visa"), "cardholder": .string("Alex Example"),
                                 "number": .string("4000000000026411"), "expiry": .string("08/29"), "cvv": .string("123")]),
        item(10, "card", "Mastercard", ["brand": .string("mastercard"), "cardholder": .string("Alex Example"),
                                        "number": .string("5555555555542290"), "expiry": .string("03/28"), "cvv": .string("456")]),
        item(11, "note", "Wi-Fi at home", ["body": .string("Network: DemoNet\nPassword: correct-horse-demo")]),
        item(12, "note", "Door code", ["body": .string("Front door 0000 (demo)")]),
        item(13, "identity", "Passport", ["name": .string("Alex Example"), "country": .string("Exampleland")]),
        item(14, "identity", "Driving licence", ["name": .string("Alex Example"), "city": .string("Sample City")]),
        item(15, "bank_account", "Everyday account", ["bank": .string("Demo Bank"), "account_holder": .string("Alex Example"),
                                                      "account_number": .string("CH93 0076 2011 6238 5295 7")]),
        item(16, "subscription", "Music", ["vendor": .string("Streamly"), "amount_minor": .int(1099), "currency": .string("EUR"),
                                           "renewal_date": .string("2026-11-01")]),
        item(17, "wifi", "Home Wi-Fi", ["ssid": .string("DemoNet"), "password": .string("correct-horse-demo"),
                                        "security": .string("wpa3")]),
        item(18, "license", "Photo editor", ["vendor": .string("Pixel Co"), "license_value": .string("DEMO-1234-5678")]),
        item(19, "api_key", "Weather API", ["service": .string("Weather"), "key": .string("demo-key-0000")]),
        item(20, "bookmark", "Docs", ["url": .string("https://example.com/docs")]),
    ]

    /// Adds every demo record that is not already there, in one commit.
    static func seed(into store: any ItemStore, now: Int64) throws {
        var snap = try store.load()
        var added = false
        for (i, (ns, raw)) in records.enumerated() {
            guard case .object(var r) = raw, case .string(let rid)? = r["id"], snap.records[rid] == nil else { continue }
            r["created_at"] = .int(now - Int64(86_400 * (i + 1))); r["updated_at"] = .int(now - Int64(3_600 * (i + 1)))
            snap.records[rid] = Wrapper.make(ns: ns, record: try Normalise.normalForm(ns: ns, record: .object(r)))
            added = true
        }
        guard added else { return }
        try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
    }
}
#endif
