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
    /** Serialization descriptor for a UTC ISO 8601 timestamp without fractional seconds (TS 119 612, 5.1.3). */
    override val descriptor: SerialDescriptor
        get() = PrimitiveSerialDescriptor(
            serialName = EtsiInstantSerializer::class.qualifiedName!!,
            kind = PrimitiveKind.STRING
        )

    override fun serialize(encoder: Encoder, value: Instant) {
        require(value.nanosecondsOfSecond == 0) {
            "Expected no second fractions, but got ${value}."
        }
        val encoded = value.toString()
        require(FORMAT.matches(encoded)) { "Expected a four-digit year and UTC seconds, but got $encoded." }
        encoder.encodeString(encoded)
    }

    override fun deserialize(decoder: Decoder) = decoder.decodeString().also {
        require('.' !in it) {
            "Expected no second fractions, but got ${it}."
        }
        require(it.endsWith("Z")) {
            "Expected a datetime in UTC, but got $it"
        }
        require(FORMAT.matches(it)) { "Expected a four-digit year and UTC seconds, but got $it." }
    }.let {
        Instant.parse(it)
    }

    private companion object {
        val FORMAT = Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
    }
}


