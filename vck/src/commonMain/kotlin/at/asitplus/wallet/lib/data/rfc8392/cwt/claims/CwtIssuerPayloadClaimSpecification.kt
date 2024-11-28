package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.primitives.StringOrURI
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.1.  iss (Issuer) Claim
 *
 *    The "iss" (issuer) claim has the same meaning and processing rules as
 *    the "iss" claim defined in Section 4.1.1 of [RFC7519], except that
 *    the value is a StringOrURI, as defined in Section 2 of this
 *    specification.  The Claim Key 1 is used to identify this claim.
 */
data object CwtIssuerPayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "iss"
    const val KEY = 1L

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
        val iss: StringOrURI?
    }

    val CwtPayloadClaimSpecification.Companion.iss: CwtIssuerPayloadClaimSpecification
        get() = CwtIssuerPayloadClaimSpecification
}