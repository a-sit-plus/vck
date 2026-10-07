package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyOrLegalNoticeItem(
    /** Localized text of the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    @SerialName(SerialNames.LEGAL_NOTICE)
    val legalNotice: MultilingualCharacterString? = null,
    /** Localized pointer to the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    @SerialName(SerialNames.POLICY)
    val policy: MultilingualPointer? = null,
) {
    object SerialNames {
        /** Wire member name `LoTEPolicy`. */
        const val POLICY = "LoTEPolicy"
        /** Wire member name `LoTELegalNotice`. */
        const val LEGAL_NOTICE = "LoTELegalNotice"
    }
}