package at.asitplus.rfc6749OAuth2AuthorizationFramework

import kotlinx.serialization.Serializable

/**
 * grammar token `response-type` of https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
 *
 * The OAuth 2.0 specification allows for registration of space-separated response_type parameter values. If a
 * Response Type contains one of more space characters (%20), it is compared as a space-delimited list of values in
 * which the order of values does not matter.
 */
@Serializable(with = ResponseTypeSpaceSeparatedSerializer::class)
data class ResponseType(
    val responseTypeNames: List<ResponseTypeName>,
) {
    init {
        require(responseTypeNames.isNotEmpty()) {
            "Expected string to satisfy grammar `response-name *( SP response-name )`, but got: $this"
        }
    }

    companion object {
        operator fun invoke(string: String) = ResponseType(string.split(" ").map {
            ResponseTypeName(it)
        })
        operator fun invoke(strings: List<String>) = ResponseType(strings.map {
            ResponseTypeName(it)
        })
    }

    override fun toString() = responseTypeNames.joinToString(" ") {
        it.toString()
    }

    operator fun contains(string: String) = responseTypeNames.any {
        it.toString() == string
    }

    /**
     * If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
     * values in which the order of values does not matter.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ResponseType

        if (sortedResponseTypeNames() != other.sortedResponseTypeNames()) return false

        return true
    }

    /**
     * If a Response Type contains one of more space characters (%20), it is compared as a space-delimited list of
     * values in which the order of values does not matter.
     */
    override fun hashCode(): Int {
        var result = sortedResponseTypeNames().hashCode()
        return result
    }

    private fun sortedResponseTypeNames() = responseTypeNames.sortedBy {
        it.toString()
    }
}


