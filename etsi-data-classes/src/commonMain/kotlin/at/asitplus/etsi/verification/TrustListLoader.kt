package at.asitplus.etsi.verification

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.utils.io.InternalAPI
import io.matthewnelson.encoding.base64.Base64
import kotlinx.serialization.json.Json
import io.ktor.util.decodeBase64String
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject


class TrustListLoader {
    private val httpClient = HttpClient {
        install(ContentNegotiation) {
            json(joseCompliantSerializer)
        }
    }

    /**
     * Fetches the Trust List across any target platform (iOS, Android, JVM, etc.)
     */
    @OptIn(InternalAPI::class)
    suspend fun fetchTrustList(): ListOfTrustedEntities? {
        val url = "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json"

        val response = httpClient.get(url) {
            accept(ContentType.Application.Json)
        }

        val jwsCompactString = response.body<String>()

        // Deserialize the JWS directly.
        // JwsSigned handles the Base64Url decoding and delegates JSON parsing to your jsonParser.
        val jws = JwsSigned.deserialize(
            TrustListJwsPayload.serializer(),
            jwsCompactString,
            joseCompliantSerializer
        ).getOrThrow()

        // The deserialized data is available safely on the payload property
        val ret = jws.payload.loTe
        return ret
//        val jwsCompactString = response.bodyAsText().trim('"', ' ', '\n', '\r')
//
//        val parts = jwsCompactString.split(".")
//        require(parts.size == 3) {
//            "The response is not a valid JWS token format. Got ${parts.size} parts."
//        }
//
//        // 3. Extract and fix the missing Base64 padding on the payload
//        var base64Payload = parts[1]
//            .replace('-', '+')
//            .replace('_', '/')
//
//        // 4. Decode directly to a String using Ktor's KMP utility
//        val decodedJsonPayload = base64Payload.decodeBase64String()
//
//        // 5. Deserialize using the class-level jsonParser
//        val rootElement = jsonParser.parseToJsonElement(decodedJsonPayload)
//
//        // 6. Extract the "LoTE" object from the root
//        val loTeElement = rootElement.jsonObject["LoTE"]
//            ?: throw IllegalArgumentException("The decoded JSON does not contain the 'LoTE' key.")
//
//        // 7. Deserialize ONLY the inner object into your class
//        val ret = jsonParser.decodeFromJsonElement<ListOfTrustedEntities>(loTeElement)
//        return ret
    }
}

@Serializable
data class TrustListJwsPayload(
    @SerialName("LoTE")
    val loTe: ListOfTrustedEntities
)

