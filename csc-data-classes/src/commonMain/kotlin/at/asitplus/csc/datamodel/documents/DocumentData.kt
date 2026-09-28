package at.asitplus.csc.datamodel.documents

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Full document content, CSC Data Model 1.0.0 section 8.1. */
@Serializable
data class DocumentData(
    @SerialName("label")
    val label: String? = null,
    @SerialName("document")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val document: ByteArray,
    @SerialName("documentType")
    val documentType: DocumentType = DocumentType.SOD,
    @SerialName("circumstantialData")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val circumstantialData: ByteArray? = null,
): SignatureCreationRequestContent, SignatureRequestContent {
    override fun equals(other: Any?): Boolean = this === other || other is DocumentData &&
            label == other.label &&
            document.contentEquals(other.document) &&
            documentType == other.documentType &&
            circumstantialData.contentEquals(other.circumstantialData)

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + document.contentHashCode()
        result = 31 * result + documentType.hashCode()
        result = 31 * result + (circumstantialData?.contentHashCode() ?: 0)
        return result
    }
}