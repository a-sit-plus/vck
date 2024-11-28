package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.NotBefore
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.5.  nbf (Not Before) Claim
 *
 *    The "nbf" (not before) claim has the same meaning and processing
 *    rules as the "nbf" claim defined in Section 4.1.5 of [RFC7519],
 *    except that the value is a NumericDate, as defined in Section 2 of
 *    this specification.  The Claim Key 5 is used to identify this claim.
 */
data object CwtNotBeforePayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "nbf"
    const val KEY = 5L

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
        val nbf: NotBefore?
    }

    val CwtPayloadClaimSpecification.Companion.nbf: CwtNotBeforePayloadClaimSpecification
        get() = CwtNotBeforePayloadClaimSpecification
}