package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class MultilingualCharacterString(
    @SerialName(SerialNames.LANGUAGE)
    @Serializable(with = EtsiRfc5646LanguageTagSerializer::class)
    val language: Rfc5646LanguageTag,
    @SerialName(SerialNames.VALUE)
    val value: String,
) {
    object SerialNames {
        const val LANGUAGE = "lang"
        const val VALUE = "value"
    }
}