package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986UniformResourceIdentifier.InlineSerializer::class)
data class Rfc3986UniformResourceIdentifier(
    override val schemeName: Rfc3986UriSchemeName,
    override val authority: Rfc3986Authority? = null,
    override val path: Rfc3986UriPath,
    override val query: Rfc3986UriQuery? = null,
    override val fragment: Rfc3986UriFragment? = null,
): Rfc3986UriReference {
    init {
        if (authority != null) {
            // All of these are necessary since Rfc3986UriPathAbsoluteOrEmpty allows for the first segment to be empty
            require(path.toString().isEmpty() || path.toString().startsWith("/")) {
                "Expected path after authority to be either absolute or empty, but got `$path`."
            }
        }
    }

    override fun toString() = string

    val string: String by lazy {
        listOfNotNull(
            "$schemeName:",
            authority?.toString(true),
            path.toString(),
            query?.let { "?$it" },
            fragment?.let { "#$it" },
        ).joinToString("")
    }

    companion object {
        operator fun invoke(string: String): Rfc3986UniformResourceIdentifier {
            val reference = Rfc3986UriReference(string)
            when(reference) {
                is Rfc3986UniformResourceIdentifier -> return reference
                is Rfc3986RelativeReference -> throw IllegalArgumentException(
                    "Expected URI to contain a scheme, but none was found in `$string`."
                )
            }
        }
    }

    class InlineSerializer : KSerializer<Rfc3986UniformResourceIdentifier> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986UniformResourceIdentifier
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = Rfc3986UniformResourceIdentifier(
            decoder.decodeString()
        )
    }
}

