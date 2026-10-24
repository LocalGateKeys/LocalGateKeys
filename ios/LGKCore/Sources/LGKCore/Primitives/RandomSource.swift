/// The only way production code obtains random bytes; tests inject fixed streams.
public protocol RandomSource: Sendable {
    func bytes(count: Int) -> [UInt8]
}

/// Cryptographically secure system randomness (`SystemRandomNumberGenerator`).
public struct SystemRandomSource: RandomSource, Sendable {
    public init() {}
    public func bytes(count: Int) -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &g) }
    }
}

/// The only way production code reads the time (Unix seconds); tests inject fixed clocks.
public protocol UnixClock: Sendable {
    var now: Int64 { get }
}

public struct SystemClock: UnixClock {
    public init() {}
    public var now: Int64 {
        var ts = timespec()
        clock_gettime(CLOCK_REALTIME, &ts)
        return Int64(ts.tv_sec)
    }
}

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(ucrt)
import ucrt
#endif
