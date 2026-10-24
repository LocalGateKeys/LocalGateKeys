import Foundation
import Crypto

public enum UUID5 {
    public static func make(namespace: UUID, name: String) -> UUID {
        var data = [UInt8]()
        withUnsafeBytes(of: namespace.uuid) { data.append(contentsOf: $0) }
        data.append(contentsOf: Array(name.utf8))
        var h = Array(Insecure.SHA1.hash(data: data))[0..<16].map { $0 }
        h[6] = (h[6] & 0x0F) | 0x50
        h[8] = (h[8] & 0x3F) | 0x80
        return UUID(uuid: (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                           h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]))
    }

    /// RFC 4122 URL namespace.
    public static let namespaceURL = UUID(uuidString: "6ba7b811-9dad-11d1-80b4-00c04fd430c8")!

    public static func string(_ u: UUID) -> String { u.uuidString.lowercased() }

    /// Desktop `conflict_copy_id`: namespace is the item id when it is a hyphenated UUID, else uuid5(URL, "lgk-item:"+id).
    public static func conflictCopyID(itemID: String, contentDigest: String) -> String {
        let hyphenated = itemID.utf8.count == 36 && itemID.utf8.enumerated().allSatisfy { i, c in
            [8, 13, 18, 23].contains(i) ? c == 0x2D : (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)
        }
        let ns = hyphenated ? UUID(uuidString: itemID)! : make(namespace: namespaceURL, name: "lgk-item:" + itemID)
        return string(make(namespace: ns, name: "lgk-copy:" + contentDigest))
    }
}
