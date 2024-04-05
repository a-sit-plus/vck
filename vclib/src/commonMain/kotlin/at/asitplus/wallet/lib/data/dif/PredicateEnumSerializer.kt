package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object PredicateEnumSerializer : KSerializer<PredicateEnum> {
    class ParsingException(message: String) : Exception(message)

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(
            "PresentationDefinitionPredicateEnumSerializer",
            PrimitiveKind.STRING
        )

    override fun serialize(encoder: Encoder, value: PredicateEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): PredicateEnum {
        val valueStringified = decoder.decodeString()
        return PredicateEnum.parse(valueStringified) ?: throw ParsingException("Unsupported predicate: $valueStringified")
    }
}