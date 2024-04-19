package at.asitplus.wallet.lib.data.jsonPath

interface Rfc9535Utils {
    fun unpackStringLiteral(string: String): String
}

val rfc9535Utils by lazy {
    object : Rfc9535Utils {
        override fun unpackStringLiteral(string: String): String {
            val doubleQuotedString = if (string.startsWith("\"")) {
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
            return rfc8259Utils.unpackStringLiteral(doubleQuotedString)
        }
    }
}