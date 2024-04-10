package at.asitplus.wallet.lib.oidc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = IdTokenTypeSerializer::class)
enum class IdTokenType(val text: String) {

    SUBJECT_SIGNED("subject_signed_id_token"),
    ATTESTER_SIGNED("attester_signed_id_token")

}

object IdTokenTypeSerializer : KSerializer<IdTokenType> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("IdTokenType", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: IdTokenType) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): IdTokenType {
        val decoded = decoder.decodeString()
        return IdTokenType.entries.first { it.text == decoded }
    }
}
