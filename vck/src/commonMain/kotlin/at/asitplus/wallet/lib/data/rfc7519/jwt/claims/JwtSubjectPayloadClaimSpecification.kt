package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import kotlinx.serialization.SerialName

/**
 * 4.1.2.  "sub" (Subject) Claim
 *
 *    The "sub" (subject) claim identifies the principal that is the
 *    subject of the JWT.  The claims in a JWT are normally statements
 *    about the subject.  The subject value MUST either be scoped to be
 *    locally unique in the context of the issuer or be globally unique.
 *    The processing of this claim is generally application specific.  The
 *    "sub" value is a case-sensitive string containing a StringOrURI
 *    value.  Use of this claim is OPTIONAL.
 */
data object JwtSubjectPayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "sub"

    interface ClaimProvider {
        @SerialName(NAME)
        val sub: StringOrURI?
    }

    val JwtPayloadClaimSpecification.Companion.sub: JwtSubjectPayloadClaimSpecification
        get() = JwtSubjectPayloadClaimSpecification
}