package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MultilingualPointer(
    /** Lowercase RFC 5646 language tag identifying the language of the referenced content (TS 119 602, 6.1.4). */
    @SerialName(SerialNames.LANGUAGE)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val language: Rfc5646LanguageTag,
    /** URI pointing to content in the indicated language (TS 119 602, 6.1.4; Annex B.3). */
    @SerialName(SerialNames.URI)
    val uniformResourceIdentifier: Rfc3986UniformResourceIdentifier,
) {
    object SerialNames {
        /** Wire member name `lang`. */
        const val LANGUAGE = "lang"
        /** Wire member name `uriValue`. */
        const val URI = "uriValue"
    }
}