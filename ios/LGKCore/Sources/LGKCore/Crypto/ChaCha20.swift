/// ChaCha20 (RFC 8439: 32-byte key, 12-byte nonce, 32-bit block counter) as a resumable keystream XOR.
/// KDBX 4 uses it for the outer cipher and for protected values.
public struct ChaCha20 {
    private var state: [UInt32]
    private var block = [UInt8](repeating: 0, count: 64)
    private var used = 64

    public init(key: [UInt8], nonce: [UInt8], counter: UInt32 = 0) {
        precondition(key.count == 32 && nonce.count == 12)
        state = [0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]
        for i in 0..<8 { state.append(StreamWords.le(key, 4 * i)) }
        state.append(counter)
        for i in 0..<3 { state.append(StreamWords.le(nonce, 4 * i)) }
    }

    private mutating func refill() {
        var x = state
        @inline(__always) func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[a] &+= x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >> 16)
            x[c] &+= x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >> 20)
            x[a] &+= x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >> 24)
            x[c] &+= x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >> 25)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
            qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
        }
        for i in 0..<16 { StreamWords.store(x[i] &+ state[i], &block, 4 * i) }
        state[12] &+= 1
        used = 0
    }

    /// XORs `data` with the next keystream bytes.
    public mutating func process(_ data: inout [UInt8]) {
        for i in data.indices {
            if used == 64 { refill() }
            data[i] ^= block[used]
            used += 1
        }
    }
}

enum StreamWords {
    @inline(__always) static func le(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
    }
    @inline(__always) static func store(_ v: UInt32, _ b: inout [UInt8], _ i: Int) {
        b[i] = UInt8(v & 0xFF); b[i + 1] = UInt8((v >> 8) & 0xFF); b[i + 2] = UInt8((v >> 16) & 0xFF); b[i + 3] = UInt8(v >> 24)
    }
}
