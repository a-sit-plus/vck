package at.asitplus.csc.datamodel.documents

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Full document content, CSC Data Model 1.0.0 section 8.1. */
@Serializable
data class DocumentData(
    /** CSC Data Model 1.0.0 section 8.1: Human-readable document label. */
    @SerialName("label")
    val label: String? = null,
    /** CSC Data Model 1.0.0 section 8.1: Document bytes, encoded as Base64. */
    @SerialName("document")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val document: ByteArray,
    /** CSC Data Model 1.0.0 section 8.1: Indicates original or formatted document bytes. */
    @SerialName("documentType")
    val documentType: DocumentType = DocumentType.SOD,
    /** CSC Data Model 1.0.0 section 8.1: Optional application-defined document context. */
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
