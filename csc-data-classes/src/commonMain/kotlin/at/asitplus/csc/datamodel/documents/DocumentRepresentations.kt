package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.api.Hashes
import at.asitplus.csc.api.contentEquals
import at.asitplus.csc.api.contentHashCode
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** One or more signer-document representations, CSC Data Model 1.0.0 section 8.4. */
@Serializable
data class DocumentRepresentations(
    /** CSC Data Model 1.0.0 section 8.4: Human-readable document label. */
    @SerialName("label")
    val label: String? = null,
    /** CSC Data Model 1.0.0 section 8.4: Digests identifying available signer-document representations. */
    @SerialName("hashes")
    val hashes: Hashes,
): SignatureCreationRequestContent {
    init {
        require(hashes.isNotEmpty()) { "hashes must contain at least one hash" }
        require(hashes.all(ByteArray::isNotEmpty)) { "hashes must not contain an empty hash" }
    }

    override fun equals(other: Any?): Boolean = this === other || other is DocumentRepresentations &&
            label == other.label && hashes.contentEquals(other.hashes)

    override fun hashCode(): Int = 31 * label.hashCode() + hashes.contentHashCode()
}
