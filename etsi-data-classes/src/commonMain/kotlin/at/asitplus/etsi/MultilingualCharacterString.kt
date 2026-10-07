package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MultilingualCharacterString(
    /** Lowercase RFC 5646 language tag identifying the language of [value] (TS 119 602, 6.1.4). */
    @SerialName(SerialNames.LANGUAGE)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val language: Rfc5646LanguageTag,
    /** Localized plain text encoded using UTF-8 (TS 119 602, Annex B.2). */
    @SerialName(SerialNames.VALUE)
    val value: String,
) {
    object SerialNames {
        /** Wire member name `lang`. */
        const val LANGUAGE = "lang"
        /** Wire member name `value`. */
        const val VALUE = "value"
    }
}