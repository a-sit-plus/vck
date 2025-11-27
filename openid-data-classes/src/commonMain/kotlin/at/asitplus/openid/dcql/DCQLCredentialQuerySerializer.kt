package at.asitplus.openid.dcql

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object DCQLCredentialQuerySerializer : JsonContentPolymorphicSerializer<DCQLCredentialQuery>(DCQLCredentialQuery::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<DCQLCredentialQuery> {
        val parameters = element.jsonObject
        val credentialFormatIdentifier = parameters[DCQLCredentialQuery.SerialNames.FORMAT]?.jsonPrimitive?.content?.let {
            CredentialFormatEnum.parse(it)
        }
        return when(credentialFormatIdentifier?.coerceDeprecations()) {
            CredentialFormatEnum.MSO_MDOC -> DCQLIsoMdocCredentialQuery.serializer()
            CredentialFormatEnum.DC_SD_JWT -> DCQLSdJwtCredentialQuery.serializer()
            CredentialFormatEnum.JWT_VC -> DCQLW3CVerifiableCredentialQuery.serializer()
            else -> throw IllegalArgumentException("Credential format not recognized: ${credentialFormatIdentifier}")
        }
    }
}