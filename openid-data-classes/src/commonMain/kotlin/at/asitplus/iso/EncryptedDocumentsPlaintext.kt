package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Document response encryption (10.3.5)
 */
@Serializable
data class EncryptedDocumentsPlaintext(
    @SerialName("documents")
    val documents: Array<Document>? = null,
    @SerialName("zkDocuments")
    val zkDocuments: Array<ZkDocument>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as EncryptedDocumentsPlaintext

        if (!documents.contentEquals(other.documents)) return false
        if (!zkDocuments.contentEquals(other.zkDocuments)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = documents?.contentHashCode() ?: 0
        result = 31 * result + (zkDocuments?.contentHashCode() ?: 0)
        return result
    }
}