package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustedEntityInformation(
    @SerialName(SerialNames.TE_NAME)
    val teName: TEName,
    @SerialName(SerialNames.TE_ADDRESS)
    val teAddress: TEAddress,
    @SerialName(SerialNames.TE_INFORMATION_URI)
    val teInformationURI: List<MultilingualPointer>,
    @SerialName(SerialNames.TE_TRADE_NAME)
    val teTradeName: TETradeName? = null,
    @SerialName(SerialNames.TE_INFORMATION_EXTENSIONS)
    val teInformationExtensions: List<TEInformationExtension>? = null,
) {
    object SerialNames {
        const val TE_NAME = "TEName"
        const val TE_ADDRESS = "TEAddress"
        const val TE_INFORMATION_URI = "TEInformationURI"
        const val TE_TRADE_NAME = "TETradeName"
        const val TE_INFORMATION_EXTENSIONS = "TEInformationExtensions"
    }
}