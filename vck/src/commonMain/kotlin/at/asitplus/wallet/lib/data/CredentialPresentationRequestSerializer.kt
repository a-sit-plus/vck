package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLQuery
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

object CredentialPresentationRequestSerializer :
    JsonContentPolymorphicSerializer<CredentialPresentationRequest>(CredentialPresentationRequest::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialPresentationRequest> {
        val parameters = element.jsonObject
        return when {
            DCQLQuery.SerialNames.CREDENTIALS in parameters -> CredentialPresentationRequest.DCQLRequest.serializer()
            else -> CredentialPresentationRequest.PresentationExchangeRequest.serializer()
        }
    }
}