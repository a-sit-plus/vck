package at.asitplus.wallet.lib.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object NamespacedDeviceNameSpacesSerializer : KSerializer<DeviceNameSpaces> {

    private val mapSerializer = MapSerializer(String.serializer(), object : DeviceSignedItemListSerializer("") {})

    override val descriptor = mapSerializer.descriptor

    override fun deserialize(decoder: Decoder): DeviceNameSpaces =
        DeviceNameSpaces(NamespacedMapEntryDeserializer().let {
            MapSerializer(it.namespaceSerializer, it.itemSerializer).deserialize(decoder)
        })

    class NamespacedMapEntryDeserializer {
        lateinit var key: String

        val namespaceSerializer = NamespaceSerializer()
        val itemSerializer = DeviceSignedItemListSerializer()

        inner class NamespaceSerializer internal constructor() : KSerializer<String> {
            override val descriptor = PrimitiveSerialDescriptor("ISO namespace", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): String = decoder.decodeString().apply { key = this }

            override fun serialize(encoder: Encoder, value: String) {
                encoder.encodeString(value).also { key = value }
            }
        }

        inner class DeviceSignedItemListSerializer internal constructor() : KSerializer<DeviceSignedItemList> {
            override val descriptor = mapSerializer.descriptor

            override fun deserialize(decoder: Decoder): DeviceSignedItemList =
                decoder.decodeSerializableValue(DeviceSignedItemListSerializer(key))

            override fun serialize(encoder: Encoder, value: DeviceSignedItemList) {
                encoder.encodeSerializableValue(DeviceSignedItemListSerializer(key), value)
            }
        }
    }

    override fun serialize(encoder: Encoder, value: DeviceNameSpaces) =
        NamespacedMapEntryDeserializer().let {
            MapSerializer(it.namespaceSerializer, it.itemSerializer).serialize(encoder, value.entries)
        }
}
