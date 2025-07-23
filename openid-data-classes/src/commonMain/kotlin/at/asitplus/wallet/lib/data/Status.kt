package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-claim
 *
 * By including a "status" claim in a Referenced Token, the Issuer is referencing a mechanism to
 * retrieve status information about this Referenced Token. The claim contains members used to
 * reference to a Status List Token as defined in this specification. Other members of the "status"
 * object may be defined by other specifications. This is analogous to "cnf" claim in Section 3.1
 * of RFC7800 in which different authenticity confirmation methods can be included.
 */
@Serializable
data class Status(
    @SerialName("status_list")
    val statusList: StatusListInfo
)