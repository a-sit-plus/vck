package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex B Identifier.
 */
@Serializable
data class WrpIdentifier(
    @SerialName("type")
    val type: String,

    @SerialName("identifier")
    val identifier: String,
)
