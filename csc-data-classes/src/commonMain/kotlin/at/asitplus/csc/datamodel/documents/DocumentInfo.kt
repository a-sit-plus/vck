package at.asitplus.csc.datamodel.documents

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.csc.datamodel.basic.Attribute
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Document digest and authorization metadata, CSC Data Model 1.0.0 section 8.2. */
@Serializable
data class DocumentInfo(
    /**
     * CSC Data Model 1.0.0 section 8.2: OPTIONAL
     * Human-readable document label.
     */
    @SerialName("label")
    val label: String? = null,
    /**
     * CSC Data Model 1.0.0 section 8.2: REQUIRED
     * Document digest, encoded as Base64.
     */
    @SerialName("hash")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val hash: ByteArray,
    /**
     * CSC Data Model 1.0.0 section 8.2: OPTIONAL
     * Meaning of the supplied document digest; defaults to `dtbsr`.
     */
    @SerialName("hashType")
    val hashType: HashType? = null,
    /**
     * CSC Data Model 1.0.0 section 8.2: OPTIONAL
     * Signed document properties.
     */
    @SerialName("signed_props")
    val signedProps: List<Attribute>? = null,
    /**
     * CSC Data Model 1.0.0 section 8.2: OPTIONAL
     * Application-defined document context.
     */
    @SerialName("circumstantialData")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val circumstantialData: ByteArray? = null,
) {
    init {
        require(hash.isNotEmpty()) { "hash must not be empty" }
    }

    override fun equals(other: Any?): Boolean = this === other || other is DocumentInfo &&
            label == other.label &&
            hash.contentEquals(other.hash) &&
            hashType == other.hashType &&
            signedProps == other.signedProps &&
            circumstantialData.contentEquals(other.circumstantialData)

    override fun hashCode(): Int {
        var result = label.hashCode()
        result = 31 * result + hash.contentHashCode()
        result = 31 * result + hashType.hashCode()
        result = 31 * result + signedProps.hashCode()
        result = 31 * result + (circumstantialData?.contentHashCode() ?: 0)
        return result
    }
}
