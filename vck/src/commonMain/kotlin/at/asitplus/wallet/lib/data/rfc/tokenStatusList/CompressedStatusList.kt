package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@ExperimentalUnsignedTypes
@Serializable
data class CompressedStatusList(
    @SerialName("lst")
    val compressed: ByteArray,
    @SerialName("bits")
    val statusBitSize: TokenStatusBitSize,
    @SerialName("aggregation_uri")
    val aggregationUri: String?,
) {
    fun decompress() = StatusList(
        uncompressed = DefaultZlibService().decompress(compressed)?.toUByteArray()
            ?: throw IllegalStateException("Member `compressed` must be decompressible."),
        statusBitSize = statusBitSize,
        aggregationUri = aggregationUri,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CompressedStatusList

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
}