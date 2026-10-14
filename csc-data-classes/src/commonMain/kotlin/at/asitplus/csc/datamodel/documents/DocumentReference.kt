package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Remote document reference, CSC Data Model 1.0.0 section 8.3. */
@Serializable
data class DocumentReference(
    /**
     * CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Human-readable document label.
     */
    @SerialName("label")
    val label: String? = null,
    /**
     * CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Access method for the remote document.
     */
    @SerialName("access")
    val access: AccessControlMethod? = null,
    /**
     * CSC Data Model 1.0.0 section 8.3: REQUIRED
     * URI locating the remote document.
     */
    @SerialName("href")
    val href: String,
    /**
     * CSC Data Model 1.0.0 section 8.3: OPTIONAL
     * Integrity checksum for the remote document, represented by the structured [Hash] object (`value` is standard
     * Base64 and `algorithmOID` is a digest OID), for example
     * `{"value":"BwgJ","algorithmOID":"2.16.840.1.101.3.4.2.1"}`. CSC Data Model Bindings 1.0.0 specifies
     * SRI strings for its QES request checksum fields; VC-K follows the conflicting structured form specified by
     * ETSI TS 119 432 for model and wire representations throughout the project.
     */
    @SerialName("checksum")
    val checksum: Hash? = null,
    /**
     * CSC Data Model 1.0.0 section 8.3: OPTIONAL
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
