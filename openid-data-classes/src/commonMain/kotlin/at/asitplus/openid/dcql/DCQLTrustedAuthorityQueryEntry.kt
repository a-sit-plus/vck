package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable(with = DCQLTrustedAuthorityQueryEntrySerializer::class)
sealed interface DCQLTrustedAuthorityQueryEntry {
    val type: DCQLTrustedAuthorityType
    val values: NonEmptyList<String>

    object SerialNames {
        const val TYPE = "type"
        const val VALUES = "values"
    }
}

class DCQLTrustedAuthorityQueryEntrySerializer :
    JsonContentPolymorphicSerializer<DCQLTrustedAuthorityQueryEntry>(DCQLTrustedAuthorityQueryEntry::class) {

    override fun selectDeserializer(
        element: JsonElement
    ) = selectDeserializer(
        Json.decodeFromJsonElement(
            DCQLTrustedAuthorityQueryEntryDeserializationDisambiguator.serializer(),
            element
        )
    )

    private fun selectDeserializer(
        disambiguator: DCQLTrustedAuthorityQueryEntryDeserializationDisambiguator,
    ) = when (disambiguator.type) {
        DCQLTrustedAuthorityType.aki -> DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier.serializer()
        DCQLTrustedAuthorityType.etsi_tl -> DCQLTrustedAuthorityQueryEntryETSITrustedList.serializer()
        DCQLTrustedAuthorityType.openid_federation -> DCQLTrustedAuthorityQueryEntryOpenIDFederation.serializer()
    }
}

@Serializable
@JsonIgnoreUnknownKeys
private class DCQLTrustedAuthorityQueryEntryDeserializationDisambiguator(
    @SerialName(DCQLTrustedAuthorityQueryEntry.SerialNames.TYPE)
    val type: DCQLTrustedAuthorityType,
)