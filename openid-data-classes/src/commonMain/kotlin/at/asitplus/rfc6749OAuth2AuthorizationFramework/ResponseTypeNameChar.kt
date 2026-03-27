package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.rfc5234ABNF.Rfc5234ABNFCore
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * grammar token `response-char` of https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
 */
@Serializable
@JvmInline
value class ResponseTypeNameChar(
    val char: Char,
) {
    init {
        validate()
    }

    private fun validate() {
        Rfc5234ABNFCore.run {
            require(char == '_' || char.isAlpha() || char.isDigit()) {
                "Expected character to be '_', DIGIT or ALPHA, but was $char"
            }
        }
    }

    override fun toString() = "$char"
}