/// Salsa20/20 (8-byte nonce, 64-bit block counter) as a resumable keystream XOR: the KDBX 3 protected-value stream.
public struct Salsa20 {
    private var state: [UInt32]
    private var block = [UInt8](repeating: 0, count: 64)
    private var used = 64

    public init(key: [UInt8], nonce: [UInt8]) {
        precondition(key.count == 32 && nonce.count == 8)
        let k = (0..<8).map { StreamWords.le(key, 4 * $0) }
        state = [0x6170_7865, k[0], k[1], k[2], k[3], 0x3320_646E, StreamWords.le(nonce, 0), StreamWords.le(nonce, 4),
                 0, 0, 0x7962_2D32, k[4], k[5], k[6], k[7], 0x6B20_6574]
    }

    private mutating func refill() {
        var x = state
        @inline(__always) func r(_ v: UInt32, _ n: UInt32) -> UInt32 { (v << n) | (v >> (32 - n)) }
        @inline(__always) func qr(_ a: Int, _ b: Int, _ c: Int, _ d: Int) {
            x[b] ^= r(x[a] &+ x[d], 7); x[c] ^= r(x[b] &+ x[a], 9)
            x[d] ^= r(x[c] &+ x[b], 13); x[a] ^= r(x[d] &+ x[c], 18)
        }
        for _ in 0..<10 {
            qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
            qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
        }
        for i in 0..<16 { StreamWords.store(x[i] &+ state[i], &block, 4 * i) }
        state[8] &+= 1
        if state[8] == 0 { state[9] &+= 1 }
        used = 0
    }

    public mutating func process(_ data: inout [UInt8]) {
        for i in data.indices {
            if used == 64 { refill() }
            data[i] ^= block[used]
            used += 1
        }
    }
}
