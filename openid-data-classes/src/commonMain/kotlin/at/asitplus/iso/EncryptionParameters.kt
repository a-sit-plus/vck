package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional document request info (10.2.4)
 */
@Serializable
data class EncryptionParameters(
    /** nonce with at least 16 bytes */
    @ByteString
    @SerialName("nonce")
    val nonce: ByteArray? = null,
    /** public key of the recipient */
    @SerialName("recipientPublicKey")
    val recipientPublicKey: CoseKey,
    /** recipient certificate chain */
    @ByteString
    @SerialName("recipientCertificate")
    val recipientCertificate: List<ByteArray>? = null,
) {
    init {
        require(nonce == null || nonce.size >= 16)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EncryptionParameters

        if (nonce != null && other.nonce != null) {
            if (!nonce.contentEquals(other.nonce)) return false
        } else if (nonce == null && other.nonce != null || nonce != null && other.nonce == null) return false
        if (recipientPublicKey != other.recipientPublicKey) return false
        if (recipientCertificate != null && other.recipientCertificate != null) {
            if (recipientCertificate.size != other.recipientCertificate.size) return false
            if (!recipientCertificate.zip(other.recipientCertificate).all { (a, b) -> a.contentEquals(b) }) return false
        } else if (recipientCertificate != other.recipientCertificate) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nonce?.contentHashCode() ?: 0
        result = 31 * result + recipientPublicKey.hashCode()
        result = 31 * result + (recipientCertificate?.fold(1) { acc, arr -> 31 * acc + arr.contentHashCode() } ?: 0)
        return result
    }

}
