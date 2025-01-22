package at.asitplus.openid.dcql

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object DCQLCredentialMetadataAndValidityConstraintsSerializer :
    JsonContentPolymorphicSerializer<DCQLCredentialMetadataAndValidityConstraints>(
        DCQLCredentialMetadataAndValidityConstraints::class
    ) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<DCQLCredentialMetadataAndValidityConstraints> {
        val parameters = element.jsonObject
        return when {
            DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES in parameters -> DCQLSdJwtCredentialMetadataAndValidityConstraints.serializer()
            DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE in parameters -> DCQLIsoMdocCredentialMetadataAndValidityConstraints.serializer()
            else -> throw IllegalArgumentException("Deserializer not found")
        }
    }
}