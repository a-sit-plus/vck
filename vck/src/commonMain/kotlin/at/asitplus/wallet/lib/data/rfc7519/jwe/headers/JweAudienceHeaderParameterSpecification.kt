package at.asitplus.wallet.lib.data.rfc7519.jwe.headers

import at.asitplus.wallet.lib.data.rfc7519.primitives.Audience
import at.asitplus.wallet.lib.data.rfc7519.primitives.AudienceInlineSerializer
import kotlinx.serialization.SerialName

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
 *
 *    Section 10.4.1 of this specification registers the "iss" (issuer),
 *    "sub" (subject), and "aud" (audience) Header Parameter names for the
 *    purpose of providing unencrypted replicas of these claims in
 *    encrypted JWTs for applications that need them.  Other specifications
 *    MAY similarly register other names that are registered Claim Names as
 *    Header Parameter names, as needed.
 */
data object JweAudienceHeaderParameterSpecification : JweHeaderParameterSpecification {
    const val NAME = "aud"

    val serializer = AudienceInlineSerializer

    interface ParameterProvider {
        @SerialName(NAME)
        val aud: Audience?
    }

    val JweHeaderParameterSpecification.Companion.aud: JweAudienceHeaderParameterSpecification
        get() = JweAudienceHeaderParameterSpecification
}
