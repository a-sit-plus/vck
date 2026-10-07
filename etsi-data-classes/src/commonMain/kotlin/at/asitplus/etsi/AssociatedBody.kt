package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AssociatedBody(
    /** Formal name of the body associated with the trusted entity (TS 119 602, 6.5.5.1.2). */
    @SerialName(SerialNames.ASSOCIATED_BODY_NAME)
    val associatedBodyName: List<MultilingualCharacterString>,
    /** Official registration identifier or alternative name of the associated body (TS 119 602, 6.5.5.1.3). */
    @SerialName(SerialNames.ASSOCIATED_BODY_TRADE_NAME)
    val associatedBodyTradeName: List<MultilingualCharacterString>? = null,
    /** Postal and electronic contact addresses of the associated body (TS 119 602, 6.5.5.1.4). */
    @SerialName(SerialNames.ASSOCIATED_BODY_ADDRESS)
    val associatedBodyAddress: AssociatedBodyAddress? = null,
    /** Localized pointers to information about the associated body (TS 119 602, 6.5.5.1.5). */
    @SerialName(SerialNames.ASSOCIATED_BODY_INFORMATION_URI)
    val associatedBodyInformationURI: List<MultilingualPointer>? = null,
    /** URI identifying the type of the associated body (TS 119 602, 6.5.5.1.6). */
    @SerialName(SerialNames.ASSOCIATED_BODY_TYPE_IDENTIFIER)
    val associatedBodyTypeIdentifier: Rfc3986UniformResourceIdentifier? = null,
    /** Additional body-specific information interpreted under the scheme rules (TS 119 602, 6.5.5.1.7). */
    @SerialName(SerialNames.ASSOCIATED_BODY_INFORMATION_EXTENSION)
    val associatedBodyInformationExtensions: AssociatedBodyInformationExtensions? = null,
) {
    init {
        require(associatedBodyName.isNotEmpty()) { "Expected non-empty associatedBodyName when present." }
        require(associatedBodyTradeName?.isNotEmpty() != false) { "Expected non-empty associatedBodyTradeName when present." }
        require(associatedBodyInformationURI?.isNotEmpty() != false) { "Expected non-empty associatedBodyInformationURI when present." }
    }

    object SerialNames {
        /** Wire member name `AssociatedBodyName`. */
        const val ASSOCIATED_BODY_NAME = "AssociatedBodyName"
        /** Wire member name `AssociatedBodyTradeName`. */
        const val ASSOCIATED_BODY_TRADE_NAME = "AssociatedBodyTradeName"
        /** Wire member name `AssociatedBodyAddress`. */
        const val ASSOCIATED_BODY_ADDRESS = "AssociatedBodyAddress"
        /** Wire member name `AssociatedBodyInformationURI`. */
        const val ASSOCIATED_BODY_INFORMATION_URI = "AssociatedBodyInformationURI"
        /** Wire member name `AssociatedBodyTypeIdentifier`. */
        const val ASSOCIATED_BODY_TYPE_IDENTIFIER = "AssociatedBodyTypeIdentifier"
        /** Wire member name `AssociatedBodyInformationExtensions`. */
        const val ASSOCIATED_BODY_INFORMATION_EXTENSION = "AssociatedBodyInformationExtensions"
    }
}