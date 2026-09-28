package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.requests.SignatureRequest
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

/** Classes that may be used as content in [SignatureRequest] */
@Serializable(with = SignatureRequestContent.JsonPolymorphicSerializer::class)
sealed interface SignatureRequestContent {
    object JsonPolymorphicSerializer :
        JsonContentPolymorphicSerializer<SignatureRequestContent>(SignatureRequestContent::class) {

        override fun selectDeserializer(element: JsonElement): DeserializationStrategy<SignatureRequestContent> {
            val properties = try {
                element.jsonObject
            } catch (cause: IllegalArgumentException) {
                throw SerializationException("Signature request content must be a JSON object", cause)
            }

            val alternatives = listOf("document", "href").filter(properties::containsKey)
            if (alternatives.size != 1) {
                throw SerializationException("Signature request content must contain exactly one of document or href")
            }

            return when (alternatives.single()) {
                "document" -> DocumentData.serializer()
                "href" -> DocumentReference.serializer()
                else -> error("Unreachable")
            }
        }
    }
}
