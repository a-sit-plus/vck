package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Remote document reference, CSC Data Model 1.0.0 section 8.3. */
@Serializable
data class DocumentReference(
    /** CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Human-readable document label.
     */
    @SerialName("label")
    val label: String? = null,
    /** CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Access method for the remote document.
     */
    @SerialName("access")
    val access: AccessControlMethod? = null,
    /** CSC Data Model 1.0.0 section 8.3: REQUIRED
     * URI locating the remote document.
     */
    @SerialName("href")
    val href: String,
    /** CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Integrity checksum for the remote document.
     */
    @SerialName("checksum")
    @Serializable(with = ChecksumSerializer::class)
    val checksum: Hash? = null,
    /** CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Application-defined document context.
     */
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
        var result = label.hashCode()
        result = 31 * result + access.hashCode()
        result = 31 * result + href.hashCode()
        result = 31 * result + checksum.hashCode()
        result = 31 * result + (circumstantialData?.contentHashCode() ?: 0)
        return result
    }
}
