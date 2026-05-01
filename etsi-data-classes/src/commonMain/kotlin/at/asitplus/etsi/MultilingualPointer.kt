package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MultilingualPointer(
    @SerialName(SerialNames.LANGUAGE)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val language: Rfc5646LanguageTag,
    @SerialName(SerialNames.URI)
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    object SerialNames {
        const val LANGUAGE = "lang"
        const val URI = "uriValue"
    }
}