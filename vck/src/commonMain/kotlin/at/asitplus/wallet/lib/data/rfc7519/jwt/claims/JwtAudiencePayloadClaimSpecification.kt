package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.Audience
import at.asitplus.wallet.lib.data.rfc7519.primitives.AudienceInlineSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 4.1.3.  "aud" (Audience) Claim
 *
 *    The "aud" (audience) claim identifies the recipients that the JWT is
 *    intended for.  Each principal intended to process the JWT MUST
 *    identify itself with a value in the audience claim.  If the principal
 *    processing the claim does not identify itself with a value in the
 *    "aud" claim when this claim is present, then the JWT MUST be
 *    rejected.  In the general case, the "aud" value is an array of case-
 *    sensitive strings, each containing a StringOrURI value.  In the
 *    special case when the JWT has one audience, the "aud" value MAY be a
 *    single case-sensitive string containing a StringOrURI value.  The
 *    interpretation of audience values is generally application specific.
 *    Use of this claim is OPTIONAL.
 */
data object JwtAudiencePayloadClaimSpecification : JwtPayloadClaimSpecification {
    const val NAME = "aud"

    interface ClaimProvider {
        @SerialName(NAME)
        val aud: Audience?
    }

    val JwtPayloadClaimSpecification.Companion.aud: JwtAudiencePayloadClaimSpecification
        get() = JwtAudiencePayloadClaimSpecification
}
