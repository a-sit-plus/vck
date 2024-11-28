package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.CwtTimeToLive
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * 65534 (time to live): OPTIONAL. Unsigned integer (Major Type 0). The time to live claim, if
 * present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be
 * cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a
 * positive number.
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
        val ttl: CwtTimeToLive?
    }

    val CwtPayloadClaimSpecification.Companion.ttl: CwtTimeToLivePayloadClaimSpecification
        get() = CwtTimeToLivePayloadClaimSpecification
}

