import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#else
import Crypto
import _CryptoExtras
#endif

public enum AESCBCError: Error, Equatable { case badKeyOrIV, badLength, badPadding }

/// AES-256-CBC with PKCS#7 padding (Bitwarden EncStrings, KDBX outer cipher) and the AES-KDF key transform.
/// CommonCrypto on Apple platforms, swift-crypto's `_CryptoExtras` elsewhere.
public enum AESCBC {
    /// Decrypts and removes PKCS#7 padding; `badPadding` when the padding is not valid (wrong key, as a rule).
    public static func decrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(key.count), iv.count == 16 else { throw AESCBCError.badKeyOrIV }
        guard !data.isEmpty, data.count % 16 == 0 else { throw AESCBCError.badLength }
        let raw = try rawDecrypt(key: key, iv: iv, data: data)
        guard let pad = raw.last, (1...16).contains(pad), raw.suffix(Int(pad)).allSatisfy({ $0 == pad }) else {
            throw AESCBCError.badPadding
        }
        return Array(raw.dropLast(Int(pad)))
    }

    /// AES-ECB encryption of `block` (a multiple of 16 bytes) `rounds` times under `seed` (KeePass AES-KDF).
    public static func transform(_ block: [UInt8], seed: [UInt8], rounds: UInt64) throws -> [UInt8] {
        guard seed.count == 32, !block.isEmpty, block.count % 16 == 0 else { throw AESCBCError.badKeyOrIV }
        #if canImport(CommonCrypto)
        var cryptor: CCCryptorRef?
        guard CCCryptorCreate(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                              seed, seed.count, nil, &cryptor) == kCCSuccess, let cryptor else { throw AESCBCError.badKeyOrIV }
        defer { CCCryptorRelease(cryptor) }
        var a = block, b = [UInt8](repeating: 0, count: block.count)
        var moved = 0
        for _ in 0..<rounds {
            guard CCCryptorUpdate(cryptor, a, a.count, &b, b.count, &moved) == kCCSuccess else { throw AESCBCError.badKeyOrIV }
            swap(&a, &b)
        }
        return a
        #else
        let key = SymmetricKey(data: seed)
        var a = block
        for _ in 0..<rounds {
            for start in stride(from: 0, to: a.count, by: 16) { try AES.permute(&a[start..<start + 16], key: key) }
        }
        return a
        #endif
    }

    private static func rawDecrypt(key: [UInt8], iv: [UInt8], data: [UInt8]) throws -> [UInt8] {
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: data.count)
        var moved = 0
        let status = CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), 0, key, key.count, iv,
                             data, data.count, &out, out.count, &moved)
        guard status == kCCSuccess else { throw AESCBCError.badLength }
        return Array(out.prefix(moved))
        #else
        return Array(try AES._CBC.decrypt(data, using: SymmetricKey(data: key), iv: AES._CBC.IV(ivBytes: iv), noPadding: true))
        #endif
    }
}
