package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlinx.serialization.SerialName

/**
 * 4.1.4.  "exp" (Expiration Time) Claim
 *
 *    The "exp" (expiration time) claim identifies the expiration time on
 *    or after which the JWT MUST NOT be accepted for processing.  The
 *    processing of the "exp" claim requires that the current date/time
 *    MUST be before the expiration date/time listed in the "exp" claim.
 *    Implementers MAY provide for some small leeway, usually no more than
 *    a few minutes, to account for clock skew.  Its value MUST be a number
 *    containing a NumericDate value.  Use of this claim is OPTIONAL.
 */
data object JwtExpirationTimePayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "exp"

    interface ClaimProvider {
        @SerialName(NAME)
        val exp: NumericDate?
    }

    val JwtPayloadClaimSpecification.Companion.exp: JwtExpirationTimePayloadClaimSpecification
        get() = JwtExpirationTimePayloadClaimSpecification
}
