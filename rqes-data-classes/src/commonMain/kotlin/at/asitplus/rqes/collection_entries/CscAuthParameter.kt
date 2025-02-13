package at.asitplus.rqes.collection_entries

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class CscAuthParameter(
    /**
     * REQUIRED.
     * Specifies one of the authorization modes.
     */
    @SerialName("mode")
    val mode: AuthMode,

    /**
     * OPTIONAL-CONDITIONAL.
     * An expression defining the combination of authentication objects
     * required to authorize usage of the private key.
     * If empty, an “AND” of all authentication objects is implied.
     * Supported operators are: “AND” | “OR” | “XOR” | “(” | “)” This value
     * SHALL NOT be returned if auth/mode is not “explicit”.
     */
    @SerialName("expression")
    val expression: String? = null,

    /**
     * REQUIRED-CONDITIONAL.
     * The authentication object types available for this credential.
     * authentication This value SHALL only be returned if auth/mode is “explicit”.
     */
    @SerialName("objects")
    val objects: Collection<JsonObject>? = null,
) {

    enum class AuthMode {
        /**
         * “explicit”: the authorization process is managed by the signature
         * application, which collects authentication factors of various
         * types.
         */
        @SerialName("explicit")
        EXPLICIT,

        /**
         * “oauth2code”: the authorization process is managed by the
         * remote service using an OAuth 2.0 mechanism based on
         * authorization code as described in Section 1.3.1 of RFC 6749
         */
        @SerialName("oauth2code")
        OAUTH2,
    }

    /**
     * Defines logic of [expression] string
     * Example: "PIN AND OTP"
     * with PIN and OTP then being defined in [objects]
     */
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