package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C status block.
 */
@Serializable
data class WrpStatus(
    @SerialName("status_list")
    val statusList: WrpStatusList
)
