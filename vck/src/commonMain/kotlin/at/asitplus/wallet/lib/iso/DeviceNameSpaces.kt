package at.asitplus.wallet.lib.iso

import kotlinx.serialization.*
import kotlinx.serialization.descriptors.*
import kotlinx.serialization.encoding.*

/**
 * Convenience class with a custom serializer ([DeviceNameSpacesSerializer]) to prevent
 * usage of the type `ByteStringWrapper<Map<String, Map<String, Any>>>` in [DeviceSigned.namespaces].
 */
@Serializable(with = DeviceNameSpacesSerializer::class)
data class DeviceNameSpaces(
    val entries: Map<String, DeviceSignedItemList>
)

/**
 * Serializes [DeviceNameSpaces.entries] as a map with an "inline list",
 * having the usual key as key,
 * but serialized instances of [DeviceSignedItemList] as the values.
 */
object DeviceNameSpacesSerializer : KSerializer<DeviceNameSpaces> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        PrimitiveSerialDescriptor("key", PrimitiveKind.STRING),
        DeviceSignedItemListSerializer.descriptor,
    )

    override fun serialize(encoder: Encoder, value: DeviceNameSpaces) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                encodeStringElement(descriptor, index++, it.key)
                encodeSerializableElement(descriptor, index++, DeviceSignedItemList.serializer(), it.value)
            }
        }
    }

    override fun deserialize(decoder: Decoder): DeviceNameSpaces {
        val entries = mutableMapOf<String, DeviceSignedItemList>()
        decoder.decodeStructure(descriptor) {
            lateinit var key: String
            var value: DeviceSignedItemList
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeStringElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeSerializableElement(descriptor, index, DeviceSignedItemList.serializer())
                    entries[key] = value
                }
            }
        }
        return DeviceNameSpaces(entries)
    }
}


/**
 * Convenience class with a custom serializer ([DeviceSignedItemListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Any>>` in [DeviceNameSpaces.entries].
 */
@Serializable(with = DeviceSignedItemListSerializer::class)
data class DeviceSignedItemList(
    val entries: List<DeviceSignedItem>
)

/**
 * Serializes [DeviceSignedItemList.entries] as an "inline list",
 * having serialized instances of [DeviceSignedItem] as the values.
 */
object DeviceSignedItemListSerializer : KSerializer<DeviceSignedItemList> {

    override val descriptor: SerialDescriptor = mapSerialDescriptor(
        PrimitiveSerialDescriptor("key", PrimitiveKind.STRING),
        PrimitiveSerialDescriptor("value", PrimitiveKind.STRING) // TODO Change to `Any`
    )

    override fun serialize(encoder: Encoder, value: DeviceSignedItemList) {
        encoder.encodeStructure(descriptor) {
            var index = 0
            value.entries.forEach {
                this.encodeStringElement(descriptor, index++, it.key)
                this.encodeStringElement(descriptor, index++, it.value)
            }
        }
    }

    override fun deserialize(decoder: Decoder): DeviceSignedItemList {
        val entries = mutableListOf<DeviceSignedItem>()
        decoder.decodeStructure(descriptor) {
            lateinit var key: String
            var value: String
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == CompositeDecoder.DECODE_DONE) {
                    break
                } else if (index % 2 == 0) {
                    key = decodeStringElement(descriptor, index)
                } else if (index % 2 == 1) {
                    value = decodeStringElement(descriptor, index)
                    entries += DeviceSignedItem(key, value)
                }
            }
        }
        return DeviceSignedItemList(entries)
    }
}


/**
 * Convenience class (getting serialized in [DeviceSignedItemListSerializer]) to prevent
 * usage of the type `List<Map<String, Any>>` in [DeviceSignedItemList.entries].
 */
data class DeviceSignedItem(
    val key: String,
    // TODO Make this `Any`, but based on the credential serializer
    val value: String,
)
