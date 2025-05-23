package at.asitplus.rqes.collection_entries

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC-API v2.0.0.2
 * Entry for document to be signed
 * Used as part of [CscAuthorizationDetails]
 */
@Serializable
data class OAuthDocumentDigest (
    /**
     * REQUIRED.
     * CSC: Conditional String containing the actual Base64-
     * encoded octet-representation of the hash of the document
     */
    @SerialName("hash")
    @Serializable(ByteArrayBase64Serializer::class)
    val hash: ByteArray,

    /**
     * NOT SPECIFIED (Assume REQUIRED)
     * CSC: String containing a human-readable description of the respective
     * document
     */
    @SerialName("label")
    val label: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OAuthDocumentDigest

        if (!hash.contentEquals(other.hash)) return false
        if (label != other.label) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hash.contentHashCode()
        result = 31 * result + label.hashCode()
        return result
    }
}