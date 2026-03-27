package at.asitplus.rfc6749OAuth2AuthorizationFramework

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

class ResponseTypeNameInlineSerializer : KSerializer<ResponseTypeName> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor(
            serialName = ResponseTypeNameInlineSerializer::class.qualifiedName!!,
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