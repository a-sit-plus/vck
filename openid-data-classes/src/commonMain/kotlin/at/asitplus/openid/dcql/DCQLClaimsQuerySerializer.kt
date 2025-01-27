package at.asitplus.openid.dcql

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object DCQLClaimsQuerySerializer : JsonContentPolymorphicSerializer<DCQLClaimsQuery>(DCQLClaimsQuery::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<DCQLClaimsQuery> {
        val parameters = element.jsonObject
        return when {
            DCQLIsoMdocClaimsQuery.SerialNames.NAMESPACE in parameters || DCQLIsoMdocClaimsQuery.SerialNames.CLAIM_NAME in parameters -> DCQLIsoMdocClaimsQuery.serializer()
            else -> DCQLJsonClaimsQuery.serializer()
        }
    }
}