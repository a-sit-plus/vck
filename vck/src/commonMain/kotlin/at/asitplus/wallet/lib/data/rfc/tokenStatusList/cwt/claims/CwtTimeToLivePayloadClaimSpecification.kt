package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TimeToLive
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * source: https://www.rfc-editor.org/rfc/rfc7519
 *
 * OPTIONAL.
 * The ttl (time to live) claim, if present, MUST specify the maximum amount of time,
 * in seconds, that the Status List Token can be cached by a consumer before a fresh
 * copy SHOULD be retrieved.
 * The value of the claim MUST be a positive number encoded in JSON as a number.
 */
data object CwtTimeToLivePayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "ttl"
    const val KEY = 65534L

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
        val ttl: TimeToLive?
    }

    val CwtPayloadClaimSpecification.Companion.ttl: CwtTimeToLivePayloadClaimSpecification
        get() = CwtTimeToLivePayloadClaimSpecification
}

