package at.asitplus.rqes.collection_entries

import kotlinx.serialization.SerialName
import kotlinx.serialization.json.JsonObject

data class CscAuthParameter(
    @SerialName("mode")
    val mode: AuthMode,
    val authExpression: AuthExpressionOptions? = null,
    val authObjects: Collection<JsonObject>? = null,
) {

    enum class AuthMode {
        @SerialName("explicit")
        EXPLICIT,

        @SerialName("oauth2code")
        OAUTH2,
    }

    enum class AuthExpressionOptions {
        @SerialName("AND")
        AND,

        @SerialName("OR")
        OR,

        @SerialName("XOR")
        XOR,

        @SerialName("(")
        LEFT,

        @SerialName(")")
        RIGHT
    }
}