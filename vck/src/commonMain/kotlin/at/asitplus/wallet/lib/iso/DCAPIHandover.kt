package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class DCAPIHandover(
    // Should be set to "OpenID4VPDCAPIHandover" or "dcapi"
    val type: String,
    /** The SHA-256 hash of [OpenID4VPDCAPIHandoverInfo] or [DCAPIInfo] */
    @ByteString
    val hash: ByteArray
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DCAPIHandover

        if (type != other.type) return false
        if (!hash.contentEquals(other.hash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + hash.contentHashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<DCAPIHandover>(it)
        }.wrap()
    }

}