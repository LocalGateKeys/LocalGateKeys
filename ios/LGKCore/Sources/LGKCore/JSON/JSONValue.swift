
public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case float(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

public enum JSONError: Error, Equatable, Sendable {
    case duplicateKey
    case nonFinite
    case loneSurrogate
    case intOutOfRange
    case syntax
}

public enum Dialect: Sendable {
    /// `ensure_ascii=False`: non-ASCII stays raw UTF-8.
    case utf8
    /// `ensure_ascii=True`: every non-ASCII scalar (and U+007F) becomes `\uxxxx`.
    case ascii
}
