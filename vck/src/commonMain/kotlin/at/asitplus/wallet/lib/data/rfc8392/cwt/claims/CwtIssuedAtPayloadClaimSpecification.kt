package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.primitives.NumericDate
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.6.  iat (Issued At) Claim
 *
 *    The "iat" (issued at) claim has the same meaning and processing rules
 *    as the "iat" claim defined in Section 4.1.6 of [RFC7519], except that
 *    the value is a NumericDate, as defined in Section 2 of this
 *    specification.  The Claim Key 6 is used to identify this claim.
 */
data object CwtIssuedAtPayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "iat"
    const val KEY = 6L

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
        val iat: NumericDate?
    }

    val CwtPayloadClaimSpecification.Companion.iat: CwtIssuedAtPayloadClaimSpecification
        get() = CwtIssuedAtPayloadClaimSpecification
}