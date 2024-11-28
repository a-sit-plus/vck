package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cbor.CborTextString
import kotlinx.serialization.SerialName

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * 6.3 Referenced Token in COSE
 *
 * REQUIRED when the status list mechanism defined in this specification is used. It has the same
 * definition as the status_list claim in Section 6.2 but MUST be encoded as a StatusListInfo CBOR
 * structure with the following fields:
 */
object CwtStatusListStatusMechanismSpecification : CwtStatusMechanismSpecification {
    const val NAME = "status_list"

    override val key: CborTextString
        get() = NAME

    interface StatusMechanismProvider {
        @SerialName(NAME)
        @Suppress("PropertyName")  // intended specification name to prevent collisions
        val status_list: StatusListInfo?
    }

    val CwtStatusMechanismSpecification.Companion.status_list: CwtStatusListStatusMechanismSpecification
        get() = CwtStatusListStatusMechanismSpecification
}