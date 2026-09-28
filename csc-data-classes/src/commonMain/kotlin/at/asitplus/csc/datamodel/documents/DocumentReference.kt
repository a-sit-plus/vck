package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Remote document reference, CSC Data Model 1.0.0 section 8.3. */
@Serializable
data class DocumentReference(
    @SerialName("label")
    val label: String? = null,
    @SerialName("access")
    val access: AccessControlMethod? = null,
    @SerialName("href")
    val href: String,
    @SerialName("checksum")
    val checksum: Hash? = null,
    @SerialName("circumstantialData")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val circumstantialData: ByteArray? = null,
) : SignatureCreationRequestContent, SignatureRequestContent {
    init {
        require(href.isNotBlank()) { "href must not be blank" }
    }

    override fun equals(other: Any?): Boolean = this === other || other is DocumentReference &&
            label == other.label &&
            access == other.access &&
            href == other.href &&
            checksum == other.checksum &&
            circumstantialData.contentEquals(other.circumstantialData)

    override fun hashCode(): Int {
        var result = label?.hashCode() ?: 0
        result = 31 * result + (access?.hashCode() ?: 0)
        result = 31 * result + href.hashCode()
        result = 31 * result + (checksum?.hashCode() ?: 0)
        result = 31 * result + (circumstantialData?.contentHashCode() ?: 0)
        return result
    }
}
