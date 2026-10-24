/// One item's sync state (desktop `engine.ItemState`). `vv` is stored without zero entries.
public struct ItemState: Equatable, Sendable {
    public let itemID: String
    public let vv: [String: Int64]
    public let deleted: Bool
    public let deletedAt: Int64?
    public let item: JSONValue?

    public static let maxItemInt: Int64 = .max

    public init(itemID: String, vv: [String: Int64], deleted: Bool, deletedAt: Int64?, item: JSONValue?) throws {
        guard Identifier.isValid(itemID) else {
            throw EngineError("item_id must be 1..128 ASCII chars from [A-Za-z0-9._:-]")
        }
        try VersionVector.check(vv)
        if let at = deletedAt, !(0...VersionVector.maxCounter).contains(at) {
            throw EngineError("deleted_at must be None or an int in 0..2**53-1")
        }
        guard deleted == (item == nil) else { throw EngineError("item must be None exactly when deleted") }
        if let item {
            guard case .object = item else { throw EngineError("item must be a dict") }
            try Self.checkJSON(item, depth: 0)
            do { _ = try CanonicalJSON.encode(item, dialect: .utf8) } catch {
                throw EngineError("item is not canonical-JSON safe: \(error)")
            }
        }
        self.itemID = itemID
        self.vv = vv.filter { $0.value != 0 }
        self.deleted = deleted
        self.deletedAt = deletedAt
        self.item = item
    }

    private static func checkJSON(_ v: JSONValue, depth: Int) throws {
        if depth > 64 { throw EngineError("item nesting too deep") }
        switch v {
        case .null, .bool, .string: return
        case .int(let n): if n < -maxItemInt { throw EngineError("integer out of range") }
        case .float(let d): if !d.isFinite { throw EngineError("non-finite float in item") }
        case .array(let a): for x in a { try checkJSON(x, depth: depth + 1) }
        case .object(let o): for x in o.values { try checkJSON(x, depth: depth + 1) }
        }
    }

    func with(vv: [String: Int64], deletedAt: Int64?) -> ItemState {
        // Inputs are already validated and the merged vector stays in range.
        try! ItemState(itemID: itemID, vv: vv, deleted: deleted, deletedAt: deletedAt, item: item)
    }
}
