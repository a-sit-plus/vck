package at.asitplus.wallet.lib.data.rfc7515.headers

import kotlinx.serialization.SerialName

/**
 * 4.1.1.  "alg" (Algorithm) Header Parameter
 *
 *    The "alg" (algorithm) Header Parameter identifies the cryptographic
 *    algorithm used to secure the JWS.  The JWS Signature value is not
 *    valid if the "alg" value does not represent a supported algorithm or
 *    if there is not a key for use with that algorithm associated with the
 *    party that digitally signed or MACed the content.  "alg" values
 *    should either be registered in the IANA "JSON Web Signature and
 *    Encryption Algorithms" registry established by [JWA] or be a value
 *    that contains a Collision-Resistant Name.  The "alg" value is a case-
 *    sensitive ASCII string containing a StringOrURI value.  This Header
 *    Parameter MUST be present and MUST be understood and processed by
 *    implementations.
 *
 *    A list of defined "alg" values for this use can be found in the IANA
 *    "JSON Web Signature and Encryption Algorithms" registry established
 *    by [JWA]; the initial contents of this registry are the values
 *    defined in Section 3.1 of [JWA].
 */
object JwsAlgorithmHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "alg"

    interface ClaimProvider {
        @SerialName(NAME)
        val alg: String?
    }

    val JwsHeaderParameterSpecification.Companion.alg: JwsAlgorithmHeaderParameterSpecification
        get() = JwsAlgorithmHeaderParameterSpecification
}
