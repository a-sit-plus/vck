package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.Audience
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.3.  aud (Audience) Claim
 *
 *    The "aud" (audience) claim has the same meaning and processing rules
 *    as the "aud" claim defined in Section 4.1.3 of [RFC7519], except that
 *    the value of the audience claim is a StringOrURI when it is not an
 *    array or each of the audience array element values is a StringOrURI
 *    when the audience claim value is an array.  (StringOrURI is defined
 *    in Section 2 of this specification.)  The Claim Key 3 is used to
 *    identify this claim.
 */
data object CwtAudiencePayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "aud"
    const val KEY = 3L

    override val claimName: CwtClaimName
        get() = CwtClaimName(NAME)
    override val claimKey: CwtClaimKey
        get() = CwtClaimKey(KEY)

    interface ClaimProvider {
        /**
         * Annotations need to be applied to properties of derived classes.
         */
        @SerialName(NAME)
        @CborLabel(KEY)
        val aud: Audience?
    }

    val CwtPayloadClaimSpecification.Companion.aud: CwtAudiencePayloadClaimSpecification
        get() = CwtAudiencePayloadClaimSpecification
}

