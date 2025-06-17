package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
data class EncryptionParameters(
    /** nonce with at least 16 bytes */
    @ByteString
    @SerialName("nonce")
    val nonce: ByteArray,
    /** public key of the recipient */
    @SerialName("recipientPublicKey")
    val recipientPublicKey: CoseKey
) {
    init {
        require(nonce.size >= 16)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EncryptionParameters

        if (!nonce.contentEquals(other.nonce)) return false
        if (recipientPublicKey != other.recipientPublicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nonce.contentHashCode()
        result = 31 * result + recipientPublicKey.hashCode()
        return result
    }

}