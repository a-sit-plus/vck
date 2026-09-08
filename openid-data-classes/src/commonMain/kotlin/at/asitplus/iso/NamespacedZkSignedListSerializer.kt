package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object NamespacedZkSignedListSerializer : KSerializer<Map<String, ZkSignedList>> {
    private val mapSerializer = MapSerializer(String.serializer(), ZkSignedListSerializer(""))

    override val descriptor = SerialDescriptor("NamespacedZkSignedList", mapSerializer.descriptor)
    override fun deserialize(decoder: Decoder): Map<String, ZkSignedList> = NamespacedMapEntryDeserializer().let {
        MapSerializer(it.namespaceSerializer, it.itemSerializer).deserialize(decoder)
    }

    class NamespacedMapEntryDeserializer {
        lateinit var key: String
        val namespaceSerializer = NamespaceSerializer()
        val itemSerializer = ItemSerializer()

        inner class NamespaceSerializer internal constructor() : KSerializer<String> {
            override val descriptor = PrimitiveSerialDescriptor("IsoNamespace", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): String = decoder.decodeString().apply { key = this }

            override fun serialize(encoder: Encoder, value: String) {
                encoder.encodeString(value).also { key = value }
            }
        }

        inner class ItemSerializer internal constructor() : KSerializer<ZkSignedList> {
            override val descriptor: SerialDescriptor = SerialDescriptor("ZkSignedList", ZkSignedListSerializer("").descriptor)

            override fun deserialize(decoder: Decoder): ZkSignedList =
                decoder.decodeSerializableValue(ZkSignedListSerializer(key))

            override fun serialize(encoder: Encoder, value: ZkSignedList) =
                encoder.encodeSerializableValue(ZkSignedListSerializer(key), value)
        }
    }

    override fun serialize(encoder: Encoder, value: Map<String, ZkSignedList>) =
        NamespacedMapEntryDeserializer().let {
            MapSerializer(it.namespaceSerializer, it.itemSerializer).serialize(encoder, value)
        }
}
