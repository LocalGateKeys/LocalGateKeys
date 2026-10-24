package app.localgatekeys.core.json

/**
 * JSON value model shared by the canonical encoder and parser.
 *
 * The nested names `Int`, `Float` and `Bool` hide the stdlib types of the same name inside this
 * interface, so stdlib types are written out in full (`kotlin.Boolean`) where both are needed.
 */
sealed interface JsonValue {
    object Null : JsonValue {
        override fun toString(): String = "Null"
    }

    data class Bool(val v: kotlin.Boolean) : JsonValue

    data class Int(val v: Long) : JsonValue

    data class Float(val v: Double) : JsonValue

    data class Str(val v: String) : JsonValue

    data class Arr(val items: List<JsonValue>) : JsonValue

    data class Obj(val fields: Map<String, JsonValue>) : JsonValue

    fun obj(): Obj = this as? Obj ?: throw IllegalArgumentException("expected object, got ${kindName()}")

    fun str(): String = (this as? Str ?: throw IllegalArgumentException("expected string, got ${kindName()}")).v

    fun long(): Long = (this as? Int ?: throw IllegalArgumentException("expected integer, got ${kindName()}")).v

    fun arr(): List<JsonValue> = (this as? Arr ?: throw IllegalArgumentException("expected array, got ${kindName()}")).items

    private fun kindName(): String = when (this) {
        Null -> "null"
        is Bool -> "bool"
        is Int -> "integer"
        is Float -> "float"
        is Str -> "string"
        is Arr -> "array"
        is Obj -> "object"
    }
}

enum class Dialect {
    /** `ensure_ascii=False`: non-ASCII stays raw UTF-8. */
    UTF8,

    /** `ensure_ascii=True`: every non-ASCII code point (and U+007F) becomes `\uxxxx`. */
    ASCII,
}

class JsonException(val kind: Kind) : Exception(kind.name) {
    enum class Kind { DUPLICATE_KEY, NON_FINITE, LONE_SURROGATE, INT_OUT_OF_RANGE, SYNTAX }
}
