package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 */
@Serializable
@CborArray
data class ClientIdToHash(
    /** `client_id` from the authorization request */
    val clientId: String,
    /** Cryptographically random number with sufficient entropy (min. 16 bytes) */
    val mdocGeneratedNonce: String
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<ClientIdToHash>(it)
        }.wrap()
    }

}