package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AssociatedBody(
    @SerialName(SerialNames.ASSOCIATED_BODY_NAME)
    val associatedBodyName: List<MultilingualCharacterString>,
    @SerialName(SerialNames.ASSOCIATED_BODY_TRADE_NAME)
    val associatedBodyTradeName: List<MultilingualCharacterString>? = null,
    @SerialName(SerialNames.ASSOCIATED_BODY_ADDRESS)
    val associatedBodyAddress: AssociatedBodyAddress? = null,
    @SerialName(SerialNames.ASSOCIATED_BODY_INFORMATION_URI)
    val associatedBodyInformationURI: List<MultilingualPointer>? = null,
    @SerialName(SerialNames.ASSOCIATED_BODY_TYPE_IDENTIFIER)
    val associatedBodyTypeIdentifier: Rfc3986UniformResourceIdentifier? = null,
    @SerialName(SerialNames.ASSOCIATED_BODY_INFORMATION_EXTENSION)
    val associatedBodyInformationExtensions: AssociatedBodyInformationExtensions? = null,
) {
    object SerialNames {
        const val ASSOCIATED_BODY_NAME = "AssociatedBodyName"
        const val ASSOCIATED_BODY_TRADE_NAME = "AssociatedBodyTradeName"
        const val ASSOCIATED_BODY_ADDRESS = "AssociatedBodyAddress"
        const val ASSOCIATED_BODY_INFORMATION_URI = "AssociatedBodyInformationURI"
        const val ASSOCIATED_BODY_TYPE_IDENTIFIER = "AssociatedBodyTypeIdentifier"
        const val ASSOCIATED_BODY_INFORMATION_EXTENSION = "AssociatedBodyInformationExtensions"
    }
}