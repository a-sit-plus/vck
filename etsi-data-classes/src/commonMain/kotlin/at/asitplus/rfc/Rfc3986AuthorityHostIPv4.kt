package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986AuthorityHostIPv4.InlineSerializer::class)
data class Rfc3986AuthorityHostIPv4(
    val string: String,
): Rfc3986AuthorityHost {
    /**
     * IPv4 address with parts in order parts[0].parts[1].parts[2].parts[3]
     */
    @Transient
    val parts = splitToParts().also {
        require(it.size == 4) {
            "Expected an IPv4 address to contain exactly 4 parts, but got ${it.size} in `$string`."
        }
    }

    class InlineSerializer : KSerializer<Rfc3986AuthorityHostIPv4> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986AuthorityHostIPv4
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder) = Rfc3986AuthorityHostIPv4(decoder.decodeString())
    }

    override fun toString() = string

    private fun splitToParts() = string.split(".").also {
        it.forEachIndexed { index, it ->
            it.forEachIndexed { index, ch ->
                require(ch in '0'..'9') {
                    "Expected IPv4 address parts to consist of parts written in decimals (0-9), but got `${ch}` at index $index in `$string`."
                }
            }
            require(!it.startsWith('0')) {
                "Expected IPv4 address parts to not start with `0`, but got ${it} at part $index in `$string`."
            }
        }
    }.map {
        it.toUByte(10)
    }
}

