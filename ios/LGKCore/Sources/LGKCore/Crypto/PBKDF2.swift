import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#else
import Crypto
import _CryptoExtras
#endif

public enum PBKDF2Error: Error, Equatable { case invalidParameters }

public enum PBKDF2 {
    /// PBKDF2-HMAC-SHA256 (Bitwarden password-protected exports).
    public static func sha256(password: [UInt8], salt: [UInt8], iterations: Int, length: Int) throws -> [UInt8] {
        guard iterations > 0, iterations <= Int(UInt32.max), length > 0 else { throw PBKDF2Error.invalidParameters }
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: length)
        let padded = password + [0]  // never an empty buffer, so the pointer is never nil
        let status = padded.withUnsafeBufferPointer { pw in
            pw.withMemoryRebound(to: CChar.self) { p in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), p.baseAddress, password.count, salt, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &out, length)
            }
        }
        guard status == kCCSuccess else { throw PBKDF2Error.invalidParameters }
        return out
        #else
        let key = try KDF.Insecure.PBKDF2.deriveKey(from: password, salt: salt, using: .sha256, outputByteCount: length,
                                                    unsafeUncheckedRounds: iterations)
        return key.withUnsafeBytes { Array($0) }
        #endif
    }
}
