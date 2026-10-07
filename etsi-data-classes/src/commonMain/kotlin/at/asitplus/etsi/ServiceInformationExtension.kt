package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UniformResourceIdentifier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.*

/** An open service extension; unknown content is retained (TS 119 602, 6.6.9). */
@Serializable(with = ServiceInformationExtension.Serializer::class)
data class ServiceInformationExtension(
    /** Extension content as defined by its originating scheme or profile. */
    val content: JsonElement,
) {
    constructor(serviceUniqueIdentifier: Rfc3986UniformResourceIdentifier) : this(buildJsonObject {
        put(SerialNames.SERVICE_UNIQUE_IDENTIFIER, serviceUniqueIdentifier.string)
    })

    /** Scheme-specific unique service identifier, when this is that extension (TS 119 602, 6.6.9.1). */
    val serviceUniqueIdentifier: Rfc3986UniformResourceIdentifier?
        get() = (content as? JsonObject)?.get(SerialNames.SERVICE_UNIQUE_IDENTIFIER)
            ?.jsonPrimitive?.content?.let { Rfc3986UniformResourceIdentifier(it) }

    object SerialNames {
        /** Wire member name `ServiceUniqueIdentifier`. */
        const val SERVICE_UNIQUE_IDENTIFIER = "ServiceUniqueIdentifier"
    }

    object Serializer : KSerializer<ServiceInformationExtension> {
        /** Descriptor of the open JSON extension content. */
        override val descriptor = JsonElement.serializer().descriptor
        override fun serialize(encoder: Encoder, value: ServiceInformationExtension) =
            encoder.encodeSerializableValue(JsonElement.serializer(), value.content)
        override fun deserialize(decoder: Decoder) =
            ServiceInformationExtension(decoder.decodeSerializableValue(JsonElement.serializer()))
    }
}
