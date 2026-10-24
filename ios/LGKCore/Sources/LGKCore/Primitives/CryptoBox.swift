import Crypto

public enum CryptoBoxError: Error, Equatable { case badKeyOrNonce, authenticationFailed }

public enum CryptoBox {
    public static func hkdf(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt,
                                         info: info, outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }

    /// Returns ciphertext || 16-byte tag.
    public static func sealGCM(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard key.count == 32, nonce.count == 12, let n = try? AES.GCM.Nonce(data: nonce) else {
            throw CryptoBoxError.badKeyOrNonce
        }
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: aad)
        return Array(box.ciphertext) + Array(box.tag)
    }

    /// Input is ciphertext || tag.
    public static func openGCM(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8], aad: [UInt8]) throws -> [UInt8] {
        guard key.count == 32, nonce.count == 12, let n = try? AES.GCM.Nonce(data: nonce) else {
            throw CryptoBoxError.badKeyOrNonce
        }
        guard ciphertext.count >= 16 else { throw CryptoBoxError.authenticationFailed }
        let split = ciphertext.count - 16
        do {
            let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ciphertext[..<split], tag: ciphertext[split...])
            return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
        } catch { throw CryptoBoxError.authenticationFailed }
    }
}
