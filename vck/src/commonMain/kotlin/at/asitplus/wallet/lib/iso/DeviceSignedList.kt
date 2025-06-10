package at.asitplus.wallet.lib.iso

import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable

/**
 * Convenience class to prevent
 * usage of the type `ByteStringWrapper<Map<String, Map<String, Any>>>` in [DeviceSigned.namespaces].
 */
@Serializable(with = NamespacedDeviceNameSpacesSerializer::class)
data class DeviceNameSpaces(
    val entries: Map<String, @Contextual DeviceSignedItemList>,
)

/**
 * Convenience class with a custom serializer ([DeviceSignedItemListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Any>>` in [DeviceNameSpaces.entries].
 */
data class DeviceSignedItemList(
    val entries: List<DeviceSignedItem>,
)

/**
 * Convenience class (getting serialized in [DeviceSignedItemListSerializer]) to prevent
 * usage of the type `List<Map<String, Any>>` in [DeviceSignedItemList.entries].
 */
data class DeviceSignedItem(
    val key: String,
    val value: Any,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceSignedItem

        if (key != other.key) return false
        if (value is ByteArray && other.value is ByteArray) return value.contentEquals(other.value)
        if (value is IntArray && other.value is IntArray) return value.contentEquals(other.value)
        if (value is BooleanArray && other.value is BooleanArray) return value.contentEquals(other.value)
        if (value is CharArray && other.value is CharArray) return value.contentEquals(other.value)
        if (value is ShortArray && other.value is ShortArray) return value.contentEquals(other.value)
        if (value is LongArray && other.value is LongArray) return value.contentEquals(other.value)
        if (value is FloatArray && other.value is FloatArray) return value.contentEquals(other.value)
        if (value is DoubleArray && other.value is DoubleArray) return value.contentEquals(other.value)
        return if (value is Array<*> && other.value is Array<*>) value.contentDeepEquals(other.value)
        else value == other.value
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + value.hashCode()
        return result
    }
}
