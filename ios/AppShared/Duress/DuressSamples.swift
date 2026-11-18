import Foundation
import LGKCore

/// A few plausible items for a new second vault (desktop `_sample_items`, Android `DuressSamples`): the owner's most
/// used user name on two common sites with random passwords and two notes, titled in the person's language. The
/// real vault's licence states (signed, no secrets) are copied as they are, so Pro does not vanish there.
public enum DuressSamples {
    private static let alphabet = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    static func password(_ random: any RandomSource) -> String {
        var out = ""
        while out.count < 16 {
            let b = Int(random.bytes(count: 1)[0])
            if b < 4 * alphabet.count { out.append(alphabet[b % alphabet.count]) }   // no modulo bias
        }
        return out
    }

    static func mostUsedUsername(_ real: StoreSnapshot) -> String {
        var counts: [String: Int] = [:]
        for (id, w) in real.records where real.meta[id]?.deleted != true {
            guard case .object(let o) = w, case .object(let r)? = o["record"], r["kind"] == .string("web"),
                  case .string(let u)? = r["username"], !u.isEmpty else { continue }
            counts[u, default: 0] += 1
        }
        return counts.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }.first?.key ?? ""
    }

    static func uuid4(_ random: any RandomSource) -> String {
        var b = random.bytes(count: 16)
        b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
        let h = Array(b.map { String(format: "%02x", $0) }.joined())
        return [0..<8, 8..<12, 12..<16, 16..<20, 20..<32].map { String(h[$0]) }.joined(separator: "-")
    }

    private static func idOf(_ r: [String: JSONValue]) -> String {
        if case .string(let id)? = r["id"] { return id }
        return ""
    }

    private static func base(_ kind: String, now: Int64, random: any RandomSource) -> [String: JSONValue] {
        ["id": .string(uuid4(random)), "kind": .string(kind), "created_at": .int(now), "updated_at": .int(now),
         "favorite": .bool(false), "tags": .array([])]
    }

    /// The new vault's records (wrapped), from the real vault's snapshot.
    public static func records(real: StoreSnapshot, random: any RandomSource, now: Int64) throws -> [String: JSONValue] {
        var out: [String: JSONValue] = [:]
        let user = mostUsedUsername(real)
        for (label, origin) in [("Wikipedia", "https://www.wikipedia.org"), ("Amazon", "https://www.amazon.com")] {
            var r = base("web", now: now, random: random)
            r["label"] = .string(label); r["username"] = .string(user); r["password"] = .string(password(random))
            r["scope"] = .object(["origin": .string(origin)])
            out[Self.idOf(r)] = Wrapper.make(ns: .entry, record: try Normalise.normalForm(ns: .entry, record: .object(r)))
        }
        let pin = random.bytes(count: 2)
        let code = String(format: "%04d", (Int(pin[0]) << 8 | Int(pin[1])) % 10000)
        let notes = [(String(localized: "Shopping list"), String(localized: "Milk\nBread\nCoffee\nApples")),
                     (String(localized: "Bike code"), String(localized: "Combination: \(code)"))]
        for (title, body) in notes {
            var r = base("note", now: now, random: random)
            r["title"] = .string(title); r["payload"] = .object(["body": .string(body)])
            out[Self.idOf(r)] = Wrapper.make(ns: .item, record: try Normalise.normalForm(ns: .item, record: .object(r)))
        }
        // Review 5a #5: the same plan in the second vault (signed licence states, no secrets).
        for (id, wrapper) in real.records where id.hasPrefix(License.idPrefix) {
            if case .object(let w) = wrapper, w["ns"] == .string(Namespace.license.rawValue) { out[id] = wrapper }
        }
        return out
    }

    /// Fills a new second vault's store.
    public static func seed(_ store: any ItemStore, real: StoreSnapshot, random: any RandomSource, now: Int64) throws {
        let snap = try store.load()
        var records = snap.records
        for (id, w) in try Self.records(real: real, random: random, now: now) { records[id] = w }
        try store.commit(StoreChange(baseRevision: snap.revision, records: records, meta: snap.meta, sync: snap.sync))
    }
}
