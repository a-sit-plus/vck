package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 */
@Serializable
@CborArray
data class OID4VPHandover(
    /** The SHA-256 hash of [ClientIdToHash] */
    @ByteString
    val clientIdHash: ByteArray,
    /** The SHA-256 hash of [ResponseUriToHash] */
    @ByteString
    val responseUriHash: ByteArray,
    /** `nonce` from the authorization request */
    val nonce: String
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OID4VPHandover

        if (!clientIdHash.contentEquals(other.clientIdHash)) return false
        if (!responseUriHash.contentEquals(other.responseUriHash)) return false
        if (nonce != other.nonce) return false

        return true
    }

    override fun hashCode(): Int {
        var result = clientIdHash.contentHashCode()
        result = 31 * result + responseUriHash.contentHashCode()
        result = 31 * result + nonce.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<OID4VPHandover>(it)
        }.wrap()
    }

}