package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex B Identifier.
 */
@Serializable
data class WrpIdentifier(
    /** URI identifying the identifier scheme, such as LEI, EORI or VATIN (clause B.2.5). */
    @SerialName("type")
    val type: String,

    /** Value identifying the legal entity within the specified scheme (clause B.2.5). */
    @SerialName("identifier")
    val identifier: String,
)
