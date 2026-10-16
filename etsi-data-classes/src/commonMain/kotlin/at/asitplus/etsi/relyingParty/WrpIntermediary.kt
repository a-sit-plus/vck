package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C intermediary reference.
 */
@Serializable
data class WrpIntermediary(
    /** Identifier of the intermediary as specified in its WRPAC (Table 10). */
    @SerialName("sub")
    val sub: String? = null,

    /** Common name of the intermediary as specified in its WRPAC (Table 10). */
    @SerialName("sname")
    val sname: String? = null
)
