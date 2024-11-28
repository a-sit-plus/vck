package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import kotlinx.serialization.SerialName

/**
 * 4.1.1.  "iss" (Issuer) Claim
 *
 *    The "iss" (issuer) claim identifies the principal that issued the
 *    JWT.  The processing of this claim is generally application specific.
 *    The "iss" value is a case-sensitive string containing a StringOrURI
 *    value.  Use of this claim is OPTIONAL.
 */
data object JwtIssuerPayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "iss"

    interface ClaimProvider {
        @SerialName(NAME)
        val iss: StringOrURI?
    }

    val JwtPayloadClaimSpecification.Companion.iss: JwtIssuerPayloadClaimSpecification
        get() = JwtIssuerPayloadClaimSpecification
}