package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyOrLegalNoticeItem(
    @SerialName(SerialNames.LEGAL_NOTICE)
    val legalNotice: MultilingualCharacterString? = null,
    @SerialName(SerialNames.POLICY)
    val policy: MultilingualPointer? = null,
) {
    object SerialNames {
        const val POLICY = "LoTEPolicy"
        const val LEGAL_NOTICE = "LoTELegalNotice"
    }
}