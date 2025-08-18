package at.asitplus.requests

import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

object AuthenticationRequestSerializer :
    JsonContentPolymorphicSerializer<AuthenticationRequest>(AuthenticationRequest::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<AuthenticationRequest> {
        //first find out if it's JAR, Oauth2 or DC-API
        with(element.jsonObject) {
            return when {
                //is JAR
                this.containsKey("request") or this.containsKey("request_uri") -> if (this.isCsc()) CscAuthRequestJar.serializer()
                    else OidcAuthRequestJar.serializer()

                //is DC-API
                this.containsKey("credentialId") -> if (this.containsKey("deviceRequest")) IsoMdocRequest.serializer()
                    else OidcAuthRequestDcApi.serializer()

                //is OAuth2
                else -> if (this.isCsc()) CscAuthRequestOAuth2.serializer()
                    else OidcAuthRequestOAuth2.serializer()
            }
        }
    }

    private fun JsonObject.isCsc(): Boolean = CscAuthRequest.getMembers().any { member ->
        this.containsKey(member)
    }
}