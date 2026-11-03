package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 475 V1.2.1 Annex C language-tagged string.
 */
@Serializable
data class WrpLangString(
    /** BCP 47 language tag identifying the language of the text (Tables 7 and 9). */
    @SerialName("lang")
    val lang: String,

    /** Localized text in the language identified by [lang] (Tables 7 and 9). */
    @SerialName("value")
    val value: String
)
