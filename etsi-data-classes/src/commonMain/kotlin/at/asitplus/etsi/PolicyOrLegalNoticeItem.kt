package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicyOrLegalNoticeItem(
    /** Plain text of the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    @SerialName(SerialNames.LEGAL_NOTICE)
    val legalNotice: String? = null,
    /** Localized pointer to the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    @SerialName(SerialNames.POLICY)
    val policy: MultilingualPointer? = null,
) {
    init {
        require((legalNotice != null) xor (policy != null)) { "Expected either a legal notice or a policy pointer." }
    }

    object SerialNames {
        /** Wire member name `LoTEPolicy`. */
        const val POLICY = "LoTEPolicy"
        /** Wire member name `LoTELegalNotice`. */
        const val LEGAL_NOTICE = "LoTELegalNotice"
    }
}