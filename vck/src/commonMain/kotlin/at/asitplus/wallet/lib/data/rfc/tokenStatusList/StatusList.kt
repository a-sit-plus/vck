package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@ExperimentalUnsignedTypes
@Serializable(with = StatusListSerializer::class)
data class StatusList(
    @SerialName("lst")
    @ByteString
    @Serializable(with = ByteArrayZlibDeflateSerializer::class)
    val uncompressed: UByteArray,
    @SerialName("bits")
    val statusBitSize: TokenStatusBitSize,
    @SerialName("aggregation_uri")
    val aggregationUri: String?,
) {
    fun toStatusListView() = StatusListView(
        uncompressed = uncompressed,
        statusBitSize = statusBitSize,
    )

    operator fun get(index: Int) = toStatusListView()[index]
    operator fun get(index: Long) = toStatusListView()[index]
    fun getOrNull(index: Long) = toStatusListView().getOrNull(index)

    fun compress() = CompressedStatusList(
        compressed = DefaultZlibService().compress(uncompressed.toByteArray())
            ?: throw IllegalStateException("Member `uncompressed` must be compressible."),
        statusBitSize = statusBitSize,
        aggregationUri = aggregationUri,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as StatusList

        if (!uncompressed.contentEquals(other.uncompressed)) return false
        if (statusBitSize != other.statusBitSize) return false
        if (aggregationUri != other.aggregationUri) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uncompressed.contentHashCode()
        result = 31 * result + statusBitSize.hashCode()
        result = 31 * result + (aggregationUri?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun StatusListView.toStatusList(aggregationUri: String?) = StatusList(
            uncompressed = uncompressed,
            statusBitSize = statusBitSize,
            aggregationUri = aggregationUri,
        )
    }
}




