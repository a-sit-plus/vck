package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

/**
 * Serialized the [ValueDigestList.entries] as an "inline map",
 * meaning [ValueDigest.key] is the map key and [ValueDigest.value] the map value,
 * for the map represented by [ValueDigestList]
 */
object ValueDigestListSerializer : KSerializer<ValueDigestList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        keyDescriptor = PrimitiveSerialDescriptor("key", PrimitiveKind.INT),
        valueDescriptor = listSerialDescriptor<Byte>(),
    )

    override fun serialize(encoder: Encoder, value: ValueDigestList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeIntElement(descriptor, index++, it.key.toInt())
                this.encodeSerializableElement(descriptor, index++, ByteArraySerializer(), it.value)
            }
        }
    }

    override fun deserialize(decoder: Decoder): ValueDigestList {
        val entries = mutableListOf<ValueDigest>()
        decoder.decodeStructure(descriptor) {
            var key = 0
            var value: ByteArray
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeIntElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeSerializableElement(descriptor, index, ByteArraySerializer())
                    entries += ValueDigest(key.toUInt(), value)
                }
            }
        }
        return ValueDigestList(entries)
    }
}