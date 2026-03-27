package at.asitplus.rfc6749OAuth2AuthorizationFramework

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * grammar token `response-name` of https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.3
 */
@Serializable(with = ResponseTypeName.InlineSerializer::class)
data class ResponseTypeName(
    private val characters: List<ResponseTypeNameChar>,
) {
    init {
        require(characters.isNotEmpty()) {
            "Expected string to satisfy grammar `1*response-char`, but got: $this"
        }
    }

    companion object {
        // constructors
        operator fun invoke(string: String) = ResponseTypeName(string.map {
            ResponseTypeNameChar(it)
        })
    }

    override fun toString() = characters.joinToString("") {
        it.char.toString()
    }

    class InlineSerializer : KSerializer<ResponseTypeName> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = ResponseTypeName::class.qualifiedName!! + "InlineSerializer",
                kind = PrimitiveKind.STRING
            )

        override fun serialize(
            encoder: Encoder,
            value: ResponseTypeName
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder): ResponseTypeName = ResponseTypeName(decoder.decodeString())
    }
}