package at.asitplus.wallet.lib.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

/**
 * Part of ISO 18013-7 Annex C
 * The outcome of the single shot encryption are the enc and cipherText values as defined in the HPKE single shot
encryption. In the EncryptedResponseData, enc is the serialized ephemeral public key, the cipherText is
the ciphertext.
 */
@Serializable
data class EncryptedResponseData(
    @ByteString
    @SerialName("enc")
    val enc: ByteArray,
    @ByteString
    @SerialName("cipherText")
    val cipherText: ByteArray,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EncryptedResponseData

        if (!enc.contentEquals(other.enc)) return false
        if (!cipherText.contentEquals(other.cipherText)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = enc.contentHashCode()
        result = 31 * result + cipherText.contentHashCode()
        return result
    }
}
