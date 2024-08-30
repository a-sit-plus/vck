package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ValueTags

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class DeviceSigned(
    @SerialName("nameSpaces")
    @ByteString
    @ValueTags(24U)
    val namespaces: ByteStringWrapper<DeviceNameSpaces>,
    @SerialName("deviceAuth")
    val deviceAuth: DeviceAuth,
) {

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
}