package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/*
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
    val cipherText: ByteArray
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<EncryptedResponseData>(it)
        }.wrap()
    }

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
