package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntityInformation(
    /** Formal name of the legal or natural person responsible for the recognized services (TS 119 602, 6.5.1). */
    @SerialName(SerialNames.TE_NAME)
    val teName: TEName,
    /** Postal and electronic contact addresses of the trusted entity (TS 119 602, 6.5.3). */
    @SerialName(SerialNames.TE_ADDRESS)
    val teAddress: TEAddress,
    /** Localized pointers to information about the trusted entity (TS 119 602, 6.5.4). */
    @SerialName(SerialNames.TE_INFORMATION_URI)
    val teInformationURI: List<MultilingualPointer>,
    /** Official registration identifier or alternative name of the trusted entity (TS 119 602, 6.5.2). */
    @SerialName(SerialNames.TE_TRADE_NAME)
    val teTradeName: TETradeName? = null,
    /** Additional entity-specific information interpreted under the scheme rules (TS 119 602, 6.5.5). */
    @SerialName(SerialNames.TE_INFORMATION_EXTENSIONS)
    val teInformationExtensions: List<TEInformationExtension>? = null,
) {
    init {
        require(teInformationURI.isNotEmpty()) { "Expected non-empty teInformationURI when present." }
        require(teInformationExtensions?.isNotEmpty() != false) { "Expected non-empty teInformationExtensions when present." }
    }

    object SerialNames {
        /** Wire member name `TEName`. */
        const val TE_NAME = "TEName"
        /** Wire member name `TEAddress`. */
        const val TE_ADDRESS = "TEAddress"
        /** Wire member name `TEInformationURI`. */
        const val TE_INFORMATION_URI = "TEInformationURI"
        /** Wire member name `TETradeName`. */
        const val TE_TRADE_NAME = "TETradeName"
        /** Wire member name `TEInformationExtensions`. */
        const val TE_INFORMATION_EXTENSIONS = "TEInformationExtensions"
    }
}