package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSizeValueSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
internal data class CborSerializableStatusList(
    @SerialName("lst")
    @ByteString
    val compressed: ByteArray,
    @Serializable(with = TokenStatusBitSizeValueSerializer::class)
    @SerialName("bits")
    val statusBitSize: TokenStatusBitSize,
    @SerialName("aggregation_uri")
    val aggregationUri: String? = null
) {
    constructor(statusList: StatusList) : this(
        compressed = statusList.compressed,
        statusBitSize = statusList.statusBitSize,
        aggregationUri = statusList.aggregationUri,
    )

    fun toStatusList() = StatusList(
        compressed = compressed,
        statusBitSize = statusBitSize,
        aggregationUri = aggregationUri,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CborSerializableStatusList

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
