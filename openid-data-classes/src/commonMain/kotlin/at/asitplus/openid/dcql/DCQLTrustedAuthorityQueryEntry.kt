package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator(DCQLTrustedAuthorityQueryEntry.SerialNames.TYPE)
sealed interface DCQLTrustedAuthorityQueryEntry {
    val type: DCQLTrustedAuthorityType
    val values: NonEmptyList<String>

    object SerialNames {
        const val TYPE = "type"
        const val VALUES = "values"
    }
}