package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

/** An open trusted-entity extension; unknown content is retained (TS 119 602, 6.5.5). */
@Serializable(with = TEInformationExtension.Serializer::class)
data class TEInformationExtension(
    /** Extension content as defined by its originating scheme or profile. */
    val content: JsonElement,
) {
    constructor(otherAssociatedBodies: List<AssociatedBody>? = null) : this(buildJsonObject {
        otherAssociatedBodies?.let { put(SerialNames.OTHER_ASSOCIATED_BODIES, Json.encodeToJsonElement(it)) }
    })

    init {
        require(otherAssociatedBodies?.isNotEmpty() != false) { "Expected non-empty OtherAssociatedBodies when present." }
    }

    /** Associated bodies, when this is the corresponding extension (TS 119 602, 6.5.5.1). */
    val otherAssociatedBodies: List<AssociatedBody>?
        get() = (content as? JsonObject)?.get(SerialNames.OTHER_ASSOCIATED_BODIES)
            ?.let { Json.decodeFromJsonElement(it) }

    object SerialNames {
        /** Wire member name `OtherAssociatedBodies`. */
        const val OTHER_ASSOCIATED_BODIES = "OtherAssociatedBodies"
    }

    object Serializer : KSerializer<TEInformationExtension> {
        /** Descriptor of the open JSON extension content. */
        override val descriptor = JsonElement.serializer().descriptor
        override fun serialize(encoder: Encoder, value: TEInformationExtension) =
            encoder.encodeSerializableValue(JsonElement.serializer(), value.content)
        override fun deserialize(decoder: Decoder) =
            TEInformationExtension(decoder.decodeSerializableValue(JsonElement.serializer()))
    }
}
