package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlinx.serialization.SerialName

/**
 * 4.1.6.  "iat" (Issued At) Claim
 *
 *    The "iat" (issued at) claim identifies the time at which the JWT was
 *    issued.  This claim can be used to determine the age of the JWT.  Its
 *    value MUST be a number containing a NumericDate value.  Use of this
 *    claim is OPTIONAL.
 */
data object JwtIssuedAtPayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "iat"

    interface ClaimProvider {
        @SerialName(NAME)
        val iat: NumericDate?
    }

    val JwtPayloadClaimSpecification.Companion.iat: JwtIssuedAtPayloadClaimSpecification
        get() = JwtIssuedAtPayloadClaimSpecification
}