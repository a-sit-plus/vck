package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * From [ARIES RFC 0434](https://github.com/hyperledger/aries-rfcs/blob/main/features/0434-outofband)
 */
@Serializable
data class OutOfBandInvitationBody(
    @SerialName("handshake_protocols")
    val handshakeProtocols: Array<String>,
    @SerialName("accept")
    val acceptTypes: Array<String>,
    @SerialName("goal_code")
    val goalCode: String,
    @SerialName("services")
    val services: Array<OutOfBandService>? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OutOfBandInvitationBody

        if (!handshakeProtocols.contentEquals(other.handshakeProtocols)) return false
        if (!acceptTypes.contentEquals(other.acceptTypes)) return false
        if (goalCode != other.goalCode) return false
        if (services != null) {
            if (other.services == null) return false
            if (!services.contentEquals(other.services)) return false
        } else if (other.services != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = handshakeProtocols.contentHashCode()
        result = 31 * result + acceptTypes.contentHashCode()
        result = 31 * result + goalCode.hashCode()
        result = 31 * result + (services?.contentHashCode() ?: 0)
        return result
    }
}