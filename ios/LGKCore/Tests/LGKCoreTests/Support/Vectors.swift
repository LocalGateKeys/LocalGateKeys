import Foundation

enum Vectors {
    /// `<repo>/tests/vectors/sync`, found from this file: Support -> LGKCoreTests -> Tests -> LGKCore -> ios -> repo.
    static let root: URL = {
        var u = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { u.deleteLastPathComponent() }
        return u.appendingPathComponent("tests/vectors/sync", isDirectory: true)
    }()

    static func url(_ relative: String) -> URL { root.appendingPathComponent(relative) }

    static func data(_ relative: String) throws -> Data { try Data(contentsOf: url(relative)) }

    static func json(_ relative: String) throws -> [String: Any] {
        guard let o = try JSONSerialization.jsonObject(with: data(relative)) as? [String: Any] else {
            throw CocoaError(.fileReadCorruptFile)
        }
        return o
    }

    static func hex(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }

    static func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
