package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Document response encryption (10.3.5)
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class EncryptedDocuments(
    @SerialName("enc")
    @ByteString
    val enc: ByteArray,
    /** Contains the encrypted [EncryptedDocumentsPlaintext] structure. */
    @SerialName("cipherText")
    @ByteString
    val cipherText: ByteArray,
    @SerialName("docRequestID")
    val docRequestId: UInt,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EncryptedDocuments) return false

        if (!enc.contentEquals(other.enc)) return false
        if (!cipherText.contentEquals(other.cipherText)) return false
        if (docRequestId != other.docRequestId) return false

        return true
    }

    override fun hashCode(): Int {
        var result = enc.contentHashCode()
        result = 31 * result + cipherText.contentHashCode()
        result = 31 * result + docRequestId.hashCode()
        return result
    }
}
