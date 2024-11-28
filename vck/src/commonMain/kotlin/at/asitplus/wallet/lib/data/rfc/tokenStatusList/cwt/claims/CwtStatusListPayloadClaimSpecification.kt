package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimKey
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtClaimName
import at.asitplus.wallet.lib.data.rfc8392.cwt.CwtPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.CborLabel

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 *  5.2. Status List Token in CWT Format
 * The status list claim MUST specify the Status List conforming to the rules outlined in Section 4.2.
 */
data object CwtStatusListPayloadClaimSpecification : CwtPayloadClaimSpecification {
    const val NAME = "status_list"
    const val KEY = 65533L

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
        @Suppress("PropertyName") // intended use of specification name to detect collisions
        val status_list: StatusList?
    }

    val CwtPayloadClaimSpecification.Companion.status_list: CwtStatusListPayloadClaimSpecification
        get() = CwtStatusListPayloadClaimSpecification
}

