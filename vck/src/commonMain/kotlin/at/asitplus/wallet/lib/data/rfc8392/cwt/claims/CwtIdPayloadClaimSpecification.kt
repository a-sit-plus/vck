package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel


/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.7.  cti (CWT ID) Claim
 *
 *    The "cti" (CWT ID) claim has the same meaning and processing rules as
 *    the "jti" claim defined in Section 4.1.7 of [RFC7519], except that
 *    the value is a byte string.  The Claim Key 7 is used to identify this
 *    claim.
 */
data object CwtIdPayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "cti"
    const val KEY = 7L

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
        @ByteString
        val cti: ByteArray?
    }

    val CwtPayloadClaimSpecification.Companion.cti: CwtIdPayloadClaimSpecification
        get() = CwtIdPayloadClaimSpecification
}