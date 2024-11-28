package at.asitplus.wallet.lib.data.rfc7519.jwe.headers

import kotlinx.serialization.SerialName

/**
 * 4.1.1.  "iss" (Issuer) Claim
 *
 *    The "iss" (issuer) claim identifies the principal that issued the
 *    JWT.  The processing of this claim is generally application specific.
 *    The "iss" value is a case-sensitive string containing a StringOrURI
 *    value.  Use of this claim is OPTIONAL.
 *
 *    Section 10.4.1 of this specification registers the "iss" (issuer),
 *    "sub" (subject), and "aud" (audience) Header Parameter names for the
 *    purpose of providing unencrypted replicas of these claims in
 *    encrypted JWTs for applications that need them.  Other specifications
 *    MAY similarly register other names that are registered Claim Names as
 *    Header Parameter names, as needed.
 */
data object JweIssuerHeaderParameterSpecification : JweHeaderParameterSpecification {
    const val NAME = "iss"

    interface ParameterProvider {
        @SerialName(JweSubjectHeaderParameterSpecification.NAME)
        val iss: String?
    }

    val JweHeaderParameterSpecification.Companion.iss: JweIssuerHeaderParameterSpecification
        get() = JweIssuerHeaderParameterSpecification
}