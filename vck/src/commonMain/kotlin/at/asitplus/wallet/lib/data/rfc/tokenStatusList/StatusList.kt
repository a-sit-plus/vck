package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import kotlinx.serialization.Serializable

@ExperimentalUnsignedTypes
@Serializable(with = StatusListSerializer::class)
data class StatusList(
    val compressed: ByteArray,
    val statusBitSize: TokenStatusBitSize,
    val aggregationUri: String?,
) {
    private val view by lazy {
        StatusListView(
            uncompressed = DefaultZlibService().decompress(compressed)?.toUByteArray()
                ?: throw IllegalStateException("Member `uncompressed` must be compressible."),
            statusBitSize = statusBitSize,
        )
    }

    fun toStatusListView() = view

    fun toStatusListSurrogate() = StatusListSurrogate(
        compressed = compressed,
        statusBitSize = statusBitSize,
        aggregationUri = aggregationUri,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as StatusList

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

    companion object {
        fun StatusListView.toStatusList(aggregationUri: String?) = StatusList(
            compressed = DefaultZlibService().compress(uncompressed.toByteArray())
                ?: throw IllegalStateException("Member `uncompressed` must be compressible."),
            statusBitSize = statusBitSize,
            aggregationUri = aggregationUri,
        )
    }
}




