package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

/**
 * Serialized as ISO8601-String with the following restrictions:
 * year with four digits, month, day, hour, minute, second (without decimal fraction) and the UTC designator "Z".
 */
class EtsiInstantSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor(
            serialName = EtsiInstantSerializer::class.qualifiedName!!,
            kind = PrimitiveKind.STRING
        )

    override fun serialize(encoder: Encoder, value: Instant) {
        require(value.nanosecondsOfSecond == 0) {
            "Expected no second fractions, but got ${value}."
        }
        encoder.encodeString(
            value.toString()
        )
    }

    override fun deserialize(decoder: Decoder) = decoder.decodeString().also {
        require('.' !in it) {
            "Expected no second fractions, but got ${it}."
        }
        require(it.endsWith("Z")) {
            "Expected a datetime in UTC, but got $it"
        }
    }.let{
        Instant.parse(it)
    }
}


