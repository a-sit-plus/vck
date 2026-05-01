package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986RelativeReference.InlineSerializer::class)
data class Rfc3986RelativeReference(
    override val authority: Rfc3986Authority? = null,
    override val path: Rfc3986RelativeReferencePath,
    override val query: Rfc3986UriQuery? = null,
    override val fragment: Rfc3986UriFragment? = null,
): Rfc3986UriReference {
    override val schemeName: Rfc3986UriSchemeName?
        get() = null
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
            authority?.toString(true),
            path.toString(),
            query?.let { "?$it" },
            fragment?.let { "#$it" },
        ).joinToString("")
    }

    companion object {
        operator fun invoke(string: String): Rfc3986RelativeReference {
            when(val reference = Rfc3986UriReference(string)) {
                is Rfc3986RelativeReference -> return reference
                is Rfc3986UniformResourceIdentifier -> throw IllegalArgumentException(
                    "Expected relative reference to contain no scheme, but got `${reference.schemeName}` in `$string`."
                )
            }
        }
    }

    class InlineSerializer : KSerializer<Rfc3986RelativeReference> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986RelativeReference
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = Rfc3986RelativeReference(
            decoder.decodeString()
        )
    }
}