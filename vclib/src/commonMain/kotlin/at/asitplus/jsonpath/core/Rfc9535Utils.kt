package at.asitplus.jsonpath.core

internal object Rfc9535Utils {
    fun switchToDoubleQuotedString(string: String) = if (string.startsWith("\"")) {
        string // treat as normal rfc8259 double quoted string
    } else {
        // switch to double quoted string
        string.substring(1, string.lastIndex)
            .replace("\\'", "'")
            .replace("\"", "\\\"")
            .let {
                "\"$it\""
            }
    }

    fun switchToSingleQuotedString(string: String) = if (string.startsWith("'")) {
        string
    } else {
        // switch to single quoted string
        string.substring(1, string.lastIndex)
            .replace("'", "\\'")
            .replace("\\\"", "\"")
            .let {
                "'$it'"
            }
    }

    fun unpackStringLiteral(string: String): String {
        val doubleQuoted = switchToDoubleQuotedString(string)
        return Rfc8259Utils.unpackStringLiteral(doubleQuoted)
    }

    fun escapeToSingleQuotedStringLiteral(string: String): String {
        val encoded = escapeToDoubleQuoted(string)
        return switchToSingleQuotedString(encoded)
    }
    fun escapeToDoubleQuoted(string: String): String {
        return Rfc8259Utils.escapeToDoubleQuotedString(string)
    }
}