package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C status block.
 */
@Serializable
data class WrpStatus(
    /** Status list reference for checking the validity of the WRPRC (Table 7; Annex C). */
    @SerialName("status_list")
    val statusList: WrpStatusList
)

@Serializable
data class WrpStatusList(
    /** Index of the WRPRC status entry in the referenced status list (Annex C). */
    @SerialName("idx")
    val idx: ULong,

    /** URI of the status list containing the WRPRC status entry (Annex C). */
    @SerialName("uri")
    val uri: String,
)
