package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.IsoDeviceRetrieval
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

/**
 * Selects the request model from its protocol-defined JSON shape because these wire objects have no shared class
 * discriminator: DCQLQuery has `credentials` (see CredentialPresentationRequestSerializerTest), ISO Device Retrieval has `deviceRequest`, and the legacy fallback is a
 * Presentation Exchange presentation definition.
 */
@Suppress("DEPRECATION")
object CredentialPresentationRequestSerializer :
    JsonContentPolymorphicSerializer<CredentialPresentationRequest>(CredentialPresentationRequest::class) {

    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<CredentialPresentationRequest> {
        val parameters = element.jsonObject
        return when {
            DCQLQuery.SerialNames.CREDENTIALS in parameters -> DCQLRequest.serializer()
            IsoDeviceRetrieval.SerialNames.DEVICE_REQUEST in parameters -> IsoDeviceRetrieval.serializer()
            else -> CredentialPresentationRequest.PresentationExchangeRequest.serializer()
        }
    }
}
