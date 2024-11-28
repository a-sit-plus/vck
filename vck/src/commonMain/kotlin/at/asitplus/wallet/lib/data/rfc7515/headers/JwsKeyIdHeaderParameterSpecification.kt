package at.asitplus.wallet.lib.data.rfc7515.headers

import kotlinx.serialization.SerialName

/**
 * 4.1.4.  "kid" (Key ID) Header Parameter
 *
 *    The "kid" (key ID) Header Parameter is a hint indicating which key
 *    was used to secure the JWS.  This parameter allows originators to
 *    explicitly signal a change of key to recipients.  The structure of
 *    the "kid" value is unspecified.  Its value MUST be a case-sensitive
 *    string.  Use of this Header Parameter is OPTIONAL.
 *
 *    When used with a JWK, the "kid" value is used to match a JWK "kid"
 *    parameter value.
 */
object JwsKeyIdHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "kid"

    interface ClaimProvider {
        @SerialName(NAME)
        val kid: String?
    }

    val JwsHeaderParameterSpecification.Companion.kid: JwsKeyIdHeaderParameterSpecification
        get() = JwsKeyIdHeaderParameterSpecification
}
