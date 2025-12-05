package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSizeValueSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

/**
 * Implements [ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) Sec. 4.3
 */
@Serializable
internal data class CborSerializableStatusList(
    /**
     * lst: REQUIRED.  CBOR Byte string (Major Type 2) that contains
     * the status values for all the Referenced Tokens it conveys
     * statuses for.  The value MUST be the compressed byte array as
     * specified in Section 4.1.
     */
    @SerialName("lst")
    @ByteString
    val compressed: ByteArray,

    /**
     * bits: REQUIRED.  CBOR Unsigned integer (Major Type 0) that
     * contains the number of bits per Referenced Token in the
     * compressed byte array (lst).  The allowed values for bits are
     * 1, 2, 4 and 8.
     */
    @SerialName("bits")
    @Serializable(with = TokenStatusBitSizeValueSerializer::class)
    val statusBitSize: TokenStatusBitSize,

    /**
     * aggregation_uri: OPTIONAL.  CBOR Text string (Major Type 3)
     * that contains a URI to retrieve the Status List Aggregation for
     * this type of Referenced Token.  See section Section 9 for
     * further detail.
     */
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
