package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListSurrogate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSizeValueSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
internal data class CborSerializableCompressedStatusList(
    @SerialName("lst")
    @ByteString
    val compressed: ByteArray,
    @Serializable(with = TokenStatusBitSizeValueSerializer::class)
    @SerialName("bits")
    val statusBitSize: TokenStatusBitSize,
    @SerialName("aggregation_uri")
    val aggregationUri: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CborSerializableCompressedStatusList

        if (!compressed.contentEquals(other.compressed)) return false
        if (statusBitSize != other.statusBitSize) return false
        if (aggregationUri != other.aggregationUri) return false

        return true
    }

    override fun hashCode(): Int {
        var result = compressed.contentHashCode()
        result = 31 * result + statusBitSize.hashCode()
        result = 31 * result + (aggregationUri?.hashCode() ?: 0)
        return result
    }

    fun toStatusListSurrogate() = StatusListSurrogate(
        compressed = compressed,
        statusBitSize = statusBitSize,
        aggregationUri = aggregationUri,
    )

    companion object {
        internal fun StatusListSurrogate.toCborSerializableCompressedStatusList() = CborSerializableCompressedStatusList(
            compressed = compressed,
            statusBitSize = statusBitSize,
            aggregationUri = aggregationUri,
        )
    }
}
