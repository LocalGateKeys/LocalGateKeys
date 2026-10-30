import CArgon2

public enum Argon2Error: Error, Equatable {
    case invalidParameters
    case failed(Int32)
}

public enum Argon2id {
    /// Raw Argon2id (version 0x13) output. The password is used exactly as given.
    public static func derive(password: [UInt8], salt: [UInt8], memoryKiB: UInt32,
                              iterations: UInt32, parallelism: UInt32, length: Int) throws -> [UInt8] {
        guard length > 0, length <= Int(UInt32.max), salt.count >= 8, parallelism > 0 else {
            throw Argon2Error.invalidParameters
        }
        var out = [UInt8](repeating: 0, count: length)
        let rc = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { s in
                out.withUnsafeMutableBufferPointer { o in
                    argon2_hash(iterations, memoryKiB, parallelism,
                                pw.baseAddress, pw.count, s.baseAddress, s.count,
                                o.baseAddress, o.count, nil, 0,
                                Argon2_id, UInt32(ARGON2_VERSION_13.rawValue))
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else { throw Argon2Error.failed(rc) }
        return out
    }
}

public enum Argon2 {
    public enum Variant: Sendable { case d, id }

    /// Raw Argon2d or Argon2id output for version 0x10 or 0x13 (KeePass KDBX 4 lets the file choose).
    public static func derive(_ variant: Variant, version: UInt32, password: [UInt8], salt: [UInt8], memoryKiB: UInt32,
                              iterations: UInt32, parallelism: UInt32, length: Int) throws -> [UInt8] {
        guard length > 0, length <= Int(UInt32.max), salt.count >= 8, parallelism > 0,
              version == 0x10 || version == 0x13 else { throw Argon2Error.invalidParameters }
        var out = [UInt8](repeating: 0, count: length)
        let type = variant == .d ? Argon2_d : Argon2_id
        let rc = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { s in
                out.withUnsafeMutableBufferPointer { o in
                    argon2_hash(iterations, memoryKiB, parallelism, pw.baseAddress, pw.count, s.baseAddress, s.count,
                                o.baseAddress, o.count, nil, 0, type, version)
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else { throw Argon2Error.failed(rc) }
        return out
    }
}
