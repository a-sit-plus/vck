package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement

/** An open associated-body extension (TS 119 602, 6.5.5.1.7). */
@Serializable(with = AssociatedBodyInformationExtension.Serializer::class)
data class AssociatedBodyInformationExtension(
    /** Extension content as defined by its originating scheme or profile, retained without modification. */
    val content: JsonElement,
) {

    object Serializer : KSerializer<AssociatedBodyInformationExtension> {
        /** Descriptor of the open JSON extension content. */
        override val descriptor = JsonElement.serializer().descriptor
        override fun serialize(encoder: Encoder, value: AssociatedBodyInformationExtension) =
            encoder.encodeSerializableValue(JsonElement.serializer(), value.content)
        override fun deserialize(decoder: Decoder) =
            AssociatedBodyInformationExtension(decoder.decodeSerializableValue(JsonElement.serializer()))
    }
}
