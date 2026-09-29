package at.asitplus.csc.datamodel.documents

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.csc.datamodel.basic.Attribute
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Document digest and authorization metadata, CSC Data Model 1.0.0 section 8.2. */
@Serializable
data class DocumentInfo(
    @SerialName("label")
    val label: String? = null,
    @SerialName("hash")
    @Serializable(with = ByteArrayBase64Serializer::class)
    val hash: ByteArray,
    @SerialName("hashType")
    val hashType: HashType? = null,
    @SerialName("signed_props")
    val signedProps: List<Attribute>? = null,
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
