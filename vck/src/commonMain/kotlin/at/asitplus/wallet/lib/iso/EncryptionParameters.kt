package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseKey
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class EncryptionParameters(
    /** nonce with at least 16 bytes */
    val nonce: String,
    /** public key of the recipient */
    val recipientPublicKey: CoseKey
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<EncryptionParameters>(it)
        }.wrap()
    }

}