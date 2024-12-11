package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class DeviceSigned(
    @SerialName("nameSpaces")
    @ValueTags(24U)
    val namespaces: ByteStringWrapper<DeviceNameSpaces>,
    @SerialName("deviceAuth")
    val deviceAuth: DeviceAuth,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceSigned

        if (namespaces != other.namespaces) return false
        if (deviceAuth != other.deviceAuth) return false

        return true
    }

    override fun hashCode(): Int {
        var result = namespaces.hashCode()
        result = 31 * result + deviceAuth.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceSigned>(it)
        }.wrap()


        // Note: Can't be a secondary constructor, because it would have the same JVM signature as the primary one.
        /**
         * Ensures the serialization of this structure in [Document.deviceSigned]:
         * ```
         * DeviceSigned = {
         *     "nameSpaces" : DeviceNameSpacesBytes ; Returned data elements
         *     "deviceAuth" : DeviceAuth            ; Contains the device authentication for mdoc authentication
         * }
         * DeviceNameSpaceBytes = #6.24(bstr .cbor DeviceNameSpaces)
         * DeviceNameSpaces = {
         *     * NameSpace => DeviceSignedItems     ; Returned data elements for each namespace
         * }
         * DeviceSignedItems = {
         *     + DataElementIdentifier => DataElementValue  ; Returned data element identifier and value
         * }
         * ```
         *
         * See ISO/IEC 18013-5:2021, 8.3.2.1.2.2 Device retrieval mdoc response
         */
        fun fromDeviceSignedItems(
            namespacedItems: Map<String, List<DeviceSignedItem>>,
            deviceAuth: CoseSigned<ByteArray>,
        ): DeviceSigned = DeviceSigned(
            namespaces = ByteStringWrapper(DeviceNameSpaces( namespacedItems.map { (namespace, value) ->
                namespace to DeviceSignedItemList(value)
            }.toMap())),
            deviceAuth = DeviceAuth(deviceAuth),
        )
    }
}