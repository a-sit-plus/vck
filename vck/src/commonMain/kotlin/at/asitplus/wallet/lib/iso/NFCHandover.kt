package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
@CborArray
data class NFCHandover(
    @ByteString
    val handoverSelect: ByteArray?,
    @ByteString
    val handoverRequest: ByteArray?
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as NFCHandover

        if (handoverSelect != null) {
            if (other.handoverSelect == null) return false
            if (!handoverSelect.contentEquals(other.handoverSelect)) return false
        } else if (other.handoverSelect != null) return false
        if (handoverRequest != null) {
            if (other.handoverRequest == null) return false
            if (!handoverRequest.contentEquals(other.handoverRequest)) return false
        } else if (other.handoverRequest != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = handoverSelect?.contentHashCode() ?: 0
        result = 31 * result + (handoverRequest?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<NFCHandover>(it)
        }.wrap()
    }

}
