package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.requests.SignatureCreationRequest
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject

/** Classes that may be used as content in [SignatureCreationRequest] */
@Serializable(with = SignatureCreationRequestContent.JsonPolymorphicSerializer::class)
sealed interface SignatureCreationRequestContent {
    object JsonPolymorphicSerializer :
        JsonContentPolymorphicSerializer<SignatureCreationRequestContent>(SignatureCreationRequestContent::class) {

        override fun selectDeserializer(element: JsonElement): DeserializationStrategy<SignatureCreationRequestContent> {
            val properties = try {
                element.jsonObject
            } catch (cause: IllegalArgumentException) {
                throw SerializationException("Signature creation request content must be a JSON object", cause)
            }

            val alternatives = listOf("document", "href", "hashes").filter(properties::containsKey)
            if (alternatives.size != 1) {
                throw SerializationException(
                    "Signature creation request content must contain exactly one of document, href, or hashes"
                )
            }

            return when (alternatives.single()) {
                "document" -> DocumentData.serializer()
                "href" -> DocumentReference.serializer()
                "hashes" -> DocumentRepresentations.serializer()
                else -> error("Unreachable")
            }
        }
    }
}
