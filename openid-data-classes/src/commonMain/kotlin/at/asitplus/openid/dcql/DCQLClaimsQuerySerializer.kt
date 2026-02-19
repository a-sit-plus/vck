package at.asitplus.openid.dcql

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object DCQLClaimsQuerySerializer : JsonContentPolymorphicSerializer<DCQLClaimsQuery>(DCQLClaimsQuery::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<DCQLClaimsQuery> {
        val parameters = element.jsonObject
        return when {
            DCQLIsoMdocClaimsQuery.SerialNames.INTENT_TO_RETAIN in parameters -> DCQLIsoMdocClaimsQuery.serializer()
            else -> DCQLAmbiguousClaimsQuery.serializer()
        }
    }
}