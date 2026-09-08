package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C language-tagged string.
 */
@Serializable
data class WrpLangString(
    @SerialName("lang")
    val lang: String,

    @SerialName("value")
    val value: String
)
