package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-list
 * Status list in its compressed form.
 */
@Serializable(with = StatusListSerializer::class)
data class StatusList(
    val compressed: ByteArray,
    val statusBitSize: TokenStatusBitSize,
    val aggregationUri: String?,
) : RevocationList() {

    override val kind: Kind = Kind.STATUS_LIST

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

    override fun toString(): String {
        return "StatusList(" +
                "aggregationUri=$aggregationUri, " +
                "statusBitSize=$statusBitSize, " +
                "compressed=${compressed.encodeToString(Base64Strict)}" +
                ")"
    }


}




