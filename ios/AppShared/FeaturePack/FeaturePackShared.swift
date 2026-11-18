import Foundation
import LGKCore

/// The kind of change the store commits on the current task make (feature pack §1.3). Edits are `update`; a sync run
/// wraps its work in `HistoryContext.$changeType.withValue(.sync) { ... }`, an import in `.import`, and so on. Read on
/// the committing thread by `LocalStore.onHistory`, so it follows the task that called `commit`.
public enum HistoryContext {
    @TaskLocal public static var changeType: ItemHistory.ChangeType = .update
}

/// Item history capture for a `LocalStore` (iPhone and Mac): the rows a commit adds, computed from the snapshot it
/// replaced. `sink` gets them (on the committing thread); it appends them to the device's local data and prunes.
public enum HistoryCapture {
    /// Installs the hook on `store`. Rows are computed inside the commit (pure, no I/O) and handed to `sink`.
    public static func install(on store: LocalStore, now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) },
                               sink: @escaping @Sendable ([ItemHistory.Row]) -> Void) {
        store.onHistory = { before, change in
            let rows = ItemHistory.rows(before: before, records: change.records, meta: change.meta,
                                        changeType: HistoryContext.changeType, now: now())
            if !rows.isEmpty { sink(rows) }
        }
    }

    /// `data` with `rows` appended and pruned to `limits` at `now`.
    public static func appending(_ rows: [ItemHistory.Row], to data: LocalData, now: Int64,
                                 limits: ItemHistory.Limits) -> LocalData {
        var out = data
        out.itemHistory = ItemHistory.prune(data.itemHistory + rows, now: now, limits: limits)
        if out.itemHistory.count > LocalData.maxHistoryRows {
            out.itemHistory = Array(out.itemHistory.suffix(LocalData.maxHistoryRows))
        }
        return out
    }
}

/// Read-only access to the iPhone's `local-data.bin` (the App's `PhoneLocalData` writes it) for the AutoFill
/// extension, which cannot link the App target: travel mode hides items from AutoFill too (§2). The constants match
/// `PhoneLocalData` exactly.
public enum PhoneLocalDataFile {
    public static let fileName = "local-data.bin"
    public static let info = Array("localgatekeys|ios-local-data|v1".utf8)
    public static let aad = Array("localgatekeys|ios-local-data|v1".utf8)
    public static let formatVersion: UInt8 = 1

    /// The local data next to `store`, or nil when it is missing or can't be read (callers then hide nothing extra).
    public static func read(for store: LocalStore) -> LocalData? {
        let url = store.directory.appendingPathComponent(fileName)
        guard let bytes = try? Array(Data(contentsOf: url)), bytes.count > 1 + 12 + 16, bytes[0] == formatVersion else {
            return nil
        }
        let key = store.derivedKey(info: info)
        guard let plain = try? CryptoBox.openGCM(key: key, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: aad)
        else { return nil }
        return try? JSONDecoder().decode(LocalData.self, from: Data(plain))
    }

    /// The travel setting in force for `store` (scan 2026-11-15 S-L4: fail closed): `missing` when there is no local
    /// data file yet, every item hidden when the file exists but can't be read, decrypted or decoded.
    public static func travel(for store: LocalStore, missing: TravelMode = .off) -> TravelMode {
        let url = store.directory.appendingPathComponent(fileName)
        guard FileManager.default.fileExists(atPath: url.path) else { return missing }
        return read(for: store)?.travel ?? .unreadableSetting
    }
}

/// Read-only access to the Mac's `local-data.bin` (the Mac app's `MacLocalStore` writes it) for the Mac AutoFill
/// extension, which cannot link the app's sources: travel mode hides items from AutoFill too (§2). The constants
/// match `MacLocalStore` exactly (checked by MacTests).
public enum MacLocalDataFile {
    public static let fileName = "local-data.bin"
    public static let info = Array("localgatekeys|mac-local-data|v1".utf8)
    public static let aad = Array("localgatekeys|mac-local-data|v1".utf8)
    public static let formatVersion: UInt8 = 1

    /// The local data next to `store`, or nil when it is missing or can't be read (callers then hide nothing extra).
    public static func read(for store: LocalStore) -> LocalData? {
        let url = store.directory.appendingPathComponent(fileName)
        guard let bytes = try? Array(Data(contentsOf: url)), bytes.count > 1 + 12 + 16, bytes[0] == formatVersion else {
            return nil
        }
        let key = store.derivedKey(info: info)
        guard let plain = try? CryptoBox.openGCM(key: key, nonce: Array(bytes[1..<13]), ciphertext: Array(bytes[13...]), aad: aad)
        else { return nil }
        return try? JSONDecoder().decode(LocalData.self, from: Data(plain))
    }

    /// The travel setting in force for `store` (scan 2026-11-15 S-L4: fail closed): `missing` when there is no local
    /// data file yet, every item hidden when the file exists but can't be read, decrypted or decoded.
    public static func travel(for store: LocalStore, missing: TravelMode = .off) -> TravelMode {
        let url = store.directory.appendingPathComponent(fileName)
        guard FileManager.default.fileExists(atPath: url.path) else { return missing }
        return read(for: store)?.travel ?? .unreadableSetting
    }
}

/// The app's current travel mode, readable from any thread (the AutoFill identity publisher runs off the main actor).
/// The app sets it when its local data opens or travel mode changes, and back to `.off` when the vault locks.
public final class TravelModeBox: @unchecked Sendable {
    public static let shared = TravelModeBox()
    private let lock = NSLock()
    private var value: TravelMode = .off
    public init() {}
    public var current: TravelMode {
        get { lock.withLock { value } }
        set { lock.withLock { value = newValue } }
    }
}

/// What travel mode and access rules take out of AutoFill on a phone (§2, §4): travel-hidden items, and logins whose
/// effective rules refuse autofill (`policy.fill`, view only on phones, expired, unknown rule).
public enum AutoFillGate {
    /// The ids AutoFill must neither publish nor offer.
    public static func omitted(_ snapshot: StoreSnapshot, travel: TravelMode, today: String) -> Set<String> {
        var out = travel.hiddenIDs(in: snapshot)
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let record)? = w["record"] else { continue }
            if !AccessRules.effective(record, device: .phone, today: today).autofill { out.insert(id) }
        }
        return out
    }

    /// `omitted` for another device class (the Mac app and its AutoFill extension pass `.computer`: view only on
    /// phones does not apply there, `policy.fill`, an expired rule and a rule from a newer version do).
    public static func omitted(_ snapshot: StoreSnapshot, travel: TravelMode, today: String,
                               device: AccessRules.DeviceClass) -> Set<String> {
        var out = travel.hiddenIDs(in: snapshot)
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let record)? = w["record"] else { continue }
            if !AccessRules.effective(record, device: device, today: today).autofill { out.insert(id) }
        }
        return out
    }

    /// The ids the widgets, the Apple Watch and the Shortcuts "Copy code" action leave out (scan 2026-11-15 S-L2):
    /// travel-hidden items, and logins whose rules need an owner check those surfaces cannot ask for (view only on
    /// phones, re-authenticate every use, expired, or a rule from a newer version). They stay pinned.
    public static func codesOmitted(_ snapshot: StoreSnapshot, travel: TravelMode, today: String) -> Set<String> {
        var out = travel.hiddenIDs(in: snapshot)
        for (id, wrapper) in snapshot.itemRecords where snapshot.meta[id]?.deleted != true {
            guard case .object(let w) = wrapper, w["ns"] == .string(Namespace.entry.rawValue),
                  case .object(let record)? = w["record"] else { continue }
            let rules = AccessRules.effective(record, device: .phone, today: today)
            if rules.phoneView || rules.reauth || rules.unknownRule { out.insert(id) }
        }
        return out
    }

    /// The rules of one login on this phone today (`.open` for anything that is not a login record).
    public static func rules(_ snapshot: StoreSnapshot, id: String, today: String) -> AccessRules.Effective {
        guard case .object(let w)? = snapshot.records[id], w["ns"] == .string(Namespace.entry.rawValue),
              case .object(let record)? = w["record"] else { return .open }
        return AccessRules.effective(record, device: .phone, today: today)
    }
}
