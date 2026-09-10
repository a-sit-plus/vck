package at.asitplus.iso


import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


class ZkSignedListSerializer(private val namespace: String) : KSerializer<ZkSignedList> {
    private val delegate = ListSerializer(ZkSignedItemSerializer(namespace))

    override val descriptor: SerialDescriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: ZkSignedList) {
        encoder.encodeSerializableValue(delegate, value.entries)
    }

    override fun deserialize(decoder: Decoder): ZkSignedList {
        return ZkSignedList(decoder.decodeSerializableValue(delegate).toList())
    }
}