package at.asitplus.wallet.lib.data.rfc7519.primitives

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object AudienceInlineSerializer : KSerializer<Audience> {
    private val serializer = ListSingleItemInlineSerializer<StringOrURI>(
        itemSerializer = StringOrURI.serializer()
    )

    override val descriptor: SerialDescriptor
        get() = serializer.descriptor

    override fun deserialize(decoder: Decoder): Audience {
        return Audience(
            serializer.deserialize(decoder)
        )
    }

    override fun serialize(encoder: Encoder, value: Audience) {
        serializer.serialize(encoder, value.value)
    }
}

