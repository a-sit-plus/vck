package at.asitplus.wallet.lib.data.rfc7519.jwt.headers

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtHeaderParameterSpecification
import kotlinx.serialization.SerialName

/**
 * 5.2.  "cty" (Content Type) Header Parameter
 *
 *    The "cty" (content type) Header Parameter defined by [JWS] and [JWE]
 *    is used by this specification to convey structural information about
 *    the JWT.
 *
 *    In the normal case in which nested signing or encryption operations
 *    are not employed, the use of this Header Parameter is NOT
 *    RECOMMENDED.  In the case that nested signing or encryption is
 *    employed, this Header Parameter MUST be present; in this case, the
 *    value MUST be "JWT", to indicate that a Nested JWT is carried in this
 *    JWT.  While media type names are not case sensitive, it is
 *    RECOMMENDED that "JWT" always be spelled using uppercase characters
 *    for compatibility with legacy implementations.  See Appendix A.2 for
 *    an example of a Nested JWT.
 */
data object JwtContentTypeHeaderParameterSpecification : JwtHeaderParameterSpecification {
    const val NAME = "cty"

    interface ParameterProvider {
        @SerialName(NAME)
        val cty: String?
    }

    val JwtHeaderParameterSpecification.Companion.cty: JwtContentTypeHeaderParameterSpecification
        get() = JwtContentTypeHeaderParameterSpecification
}
