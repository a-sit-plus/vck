package at.asitplus.rfc6749OAuth2AuthorizationFramework

import kotlinx.serialization.Serializable

/**
 * grammar token `response-name` of https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
 */
@Serializable(with = ResponseTypeNameInlineSerializer::class)
data class ResponseTypeName(
    private val characters: List<ResponseTypeNameChar>,
) {
    init {
        require(characters.isNotEmpty()) {
            "Expected string to satisfy grammar `1*response-char`, but got: $this"
        }
    }

    companion object {
        // constructors
        operator fun invoke(string: String) = ResponseTypeName(string.map {
            ResponseTypeNameChar(it)
        })
    }

    override fun toString() = characters.joinToString("") {
        it.char.toString()
    }
}

