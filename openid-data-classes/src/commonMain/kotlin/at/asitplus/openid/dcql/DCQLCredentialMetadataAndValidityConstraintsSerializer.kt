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
            parameters.isEmpty() -> DCQLEmptyCredentialMetadataAndValidityConstraints.serializer()
            DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES in parameters -> DCQLSdJwtCredentialMetadataAndValidityConstraints.serializer()
            DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE in parameters -> DCQLIsoMdocCredentialMetadataAndValidityConstraints.serializer()
            DCQLW3CVerifiableCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES in parameters -> DCQLW3CVerifiableCredentialMetadataAndValidityConstraints.serializer()
            else -> throw IllegalArgumentException("Deserializer not found")
        }
    }
}