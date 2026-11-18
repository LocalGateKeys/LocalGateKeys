import Foundation
import LGKCore
#if os(macOS)
import AppSharedMac
#else
import AppShared
#endif

/// The estate pack (sub-plan 12, Windows `estate_pack.py` and the `builtin.estate` template): a note with one
/// "## <label>" heading per field and room under each, the "Shard holders" heading pre-filled with the emergency
/// access holders' nicknames (never anything else about them). Created from Emergency access (iPhone Settings, the
/// Mac's Recovery centre); the note is an ordinary note afterwards, tagged `estate`.
enum EstatePack {
    nonisolated static let templateID = "builtin.estate"
    nonisolated static let title = String(localized: "Estate pack")
    nonisolated static let createLabel = String(localized: "Create estate pack note")
    nonisolated static let help = String(localized: "Where the will is, who the executor is, accounts to close, devices and their unlock, and who holds an emergency access share.")
    nonisolated static let created = String(localized: "Estate pack note created. Fill it in from your vault.")
    nonisolated static let failed = String(localized: "The estate pack note could not be saved on this device.")
    nonisolated static let tag = "estate"

    /// The template's fields, in order (Windows `builtin.estate`). `secret` marks the field Windows hides.
    struct Field: Equatable {
        let name: String
        let label: String
        let secret: Bool
    }

    static var fields: [Field] {
        [Field(name: "will_location", label: String(localized: "Where the will is"), secret: false),
         Field(name: "executor", label: String(localized: "Executor"), secret: false),
         Field(name: "accounts_to_close", label: String(localized: "Accounts to close"), secret: false),
         Field(name: "devices_unlock", label: String(localized: "Devices and their unlock"), secret: true),
         Field(name: "shard_holders", label: String(localized: "Shard holders"), secret: false)]
    }

    /// Windows `body`: each label as a heading followed by an empty line; holders listed by nickname only.
    static func body(holders: [String] = []) -> String {
        let names = holders.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        return fields.map { field in
            var text = "## \(field.label)\n"
            if field.name == "shard_holders" { text += names.map { "- \($0)\n" }.joined() }
            return text
        }.joined(separator: "\n")
    }

    enum Outcome: Equatable { case created(String), needsPro, failed }

    /// Adds the note to the unlocked vault in one commit (the free plan's item limit applies, as for any new item).
    static func create(in store: any ItemStore, holders: [String], isPro: Bool,
                       clock: any UnixClock = SystemClock(), random: any RandomSource = SystemRandomSource()) -> Outcome {
        do {
            var snap = try store.load()
            guard ItemLimit.allows(.create, snapshot: snap, isPro: isPro) else { return .needsPro }
            var record = EditorModel.newRecord(kind: .note, now: clock.now, random: random)
            record["title"] = .string(title)
            record["payload"] = .object(["body": .string(body(holders: holders)), "template_id": .string(templateID)])
            record["tags"] = .array([.string(tag)])
            let normal = try Normalise.normalForm(ns: .item, record: .object(record))
            guard case .object(let o) = normal, case .string(let id)? = o["id"], snap.records[id] == nil else { return .failed }
            snap.records[id] = Wrapper.make(ns: .item, record: normal)
            try store.commit(StoreChange(baseRevision: snap.revision, records: snap.records, meta: snap.meta, sync: snap.sync))
            return .created(id)
        } catch {
            return .failed
        }
    }
}
