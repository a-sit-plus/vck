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
 * 3.1.4.  exp (Expiration Time) Claim
 *
 *    The "exp" (expiration time) claim has the same meaning and processing
 *    rules as the "exp" claim defined in Section 4.1.4 of [RFC7519],
 *    except that the value is a NumericDate, as defined in Section 2 of
 *    this specification.  The Claim Key 4 is used to identify this claim.
 */
data object CwtExpirationTimePayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "exp"
    const val KEY = 4L

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
        val exp: NumericDate?
    }

    val CwtPayloadClaimSpecification.Companion.exp: CwtExpirationTimePayloadClaimSpecification
        get() = CwtExpirationTimePayloadClaimSpecification
}