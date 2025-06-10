package at.asitplus.wallet.lib.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc response (8.3.2.2.2.2)
 */
@Serializable
data class ServerResponse(
    @SerialName("version")
    val version: String,
    /**
     * A single document is a [JwsSigned], whose payload may be a `MobileDrivingLicenceJws`
     */
    @SerialName("documents")
    val documents: Array<String>,
    @SerialName("documentErrors")
    val documentErrors: Map<String, Int>? = null,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ServerResponse

        if (version != other.version) return false
        if (!documents.contentEquals(other.documents)) return false
        return documentErrors == other.documentErrors
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + documents.contentHashCode()
        result = 31 * result + (documentErrors?.hashCode() ?: 0)
        return result
    }

}