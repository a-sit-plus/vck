package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * From [ARIES RFC 0434](https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband)
 */
@Serializable
data class OutOfBandService(
    @SerialName("type")
    val type: String,
    @SerialName("recipientKeys")
    val recipientKeys: Array<String>,
    @SerialName("serviceEndpoint")
    val serviceEndpoint: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OutOfBandService

        if (type != other.type) return false
        if (!recipientKeys.contentEquals(other.recipientKeys)) return false
        if (serviceEndpoint != other.serviceEndpoint) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + recipientKeys.contentHashCode()
        result = 31 * result + serviceEndpoint.hashCode()
        return result
    }
}