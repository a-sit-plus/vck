package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement

/**
 * Separation between the originally received bytes and the decoded content allows for integrity
 * verification against vct#integrity and extends#integrity.
 *
 * When fetched over HTTP, [originalBytes] are the raw response bytes, which is what integrity
 * metadata is defined over. When deserialized from a JSON string (e.g. in tests or a registry),
 * [originalBytes] are derived from the re-serialized [JsonElement] and may differ from the
 * original source bytes if the input had extra whitespace or different key ordering.
 */
@Serializable(with = SdJwtTypeMetadataDocument.DefinitionSerializer::class)
data class SdJwtTypeMetadataDocument(
    val originalBytes: ByteArray,
    val definition: SdJwtTypeMetadataDefinition,
) {
    object DefinitionSerializer : KSerializer<SdJwtTypeMetadataDocument> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = DefinitionSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING
            )

        override fun serialize(
            encoder: Encoder,
            value: SdJwtTypeMetadataDocument,
        ) {
            encoder.encodeSerializableValue(
                JsonElement.Companion.serializer(),
                Json.Default.parseToJsonElement(value.originalBytes.decodeToString()),
            )
        }

        override fun deserialize(decoder: Decoder): SdJwtTypeMetadataDocument {
            require(decoder is JsonDecoder) {
                "Expected decoder to be JsonDecoder, but got `$decoder`."
            }

            val jsonElement = decoder.decodeJsonElement()
            val decoded = decoder.json.decodeFromJsonElement(
                SdJwtTypeMetadataDefinition.serializer(),
                jsonElement,
            )

            return SdJwtTypeMetadataDocument(
                originalBytes = jsonElement.toString().encodeToByteArray(),
                definition = decoded,
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SdJwtTypeMetadataDocument) return false
        return originalBytes.contentEquals(other.originalBytes) && definition == other.definition
    }

    override fun hashCode(): Int {
        var result = originalBytes.contentHashCode()
        result = 31 * result + definition.hashCode()
        return result
    }

    override fun toString(): String =
        "SdJwtTypeMetadataDocument(originalBytes=${originalBytes.decodeToString()}, definition=$definition)"
}
