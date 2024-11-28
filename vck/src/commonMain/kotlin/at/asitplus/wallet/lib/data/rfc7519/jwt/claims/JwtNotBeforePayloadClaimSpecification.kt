package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlinx.serialization.SerialName

/**
 * 4.1.5.  "nbf" (Not Before) Claim
 *
 *    The "nbf" (not before) claim identifies the time before which the JWT
 *    MUST NOT be accepted for processing.  The processing of the "nbf"
 *    claim requires that the current date/time MUST be after or equal to
 *    the not-before date/time listed in the "nbf" claim.  Implementers MAY
 *    provide for some small leeway, usually no more than a few minutes, to
 *    account for clock skew.  Its value MUST be a number containing a
 *    NumericDate value.  Use of this claim is OPTIONAL.
 */
data object JwtNotBeforePayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "nbf"

    interface ClaimProvider {
        @SerialName(NAME)
        val nbf: NumericDate?
    }

    val JwtPayloadClaimSpecification.Companion.nbf: JwtNotBeforePayloadClaimSpecification
        get() = JwtNotBeforePayloadClaimSpecification
}