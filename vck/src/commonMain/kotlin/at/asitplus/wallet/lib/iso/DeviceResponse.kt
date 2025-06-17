package at.asitplus.wallet.lib.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceResponse(
    @SerialName("version")
    val version: String,
    @SerialName("documents")
    val documents: Array<Document>? = null,
    @SerialName("documentErrors")
    val documentErrors: Array<Pair<String, UInt>>? = null,
    @SerialName("status")
    val status: UInt,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceResponse

        if (version != other.version) return false
        if (documents != null) {
            if (other.documents == null) return false
            if (!documents.contentEquals(other.documents)) return false
        } else if (other.documents != null) return false
        if (documentErrors != null) {
            if (other.documentErrors == null) return false
            if (!documentErrors.contentEquals(other.documentErrors)) return false
        } else if (other.documentErrors != null) return false
        return status == other.status
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + (documents?.contentHashCode() ?: 0)
        result = 31 * result + (documentErrors?.contentHashCode() ?: 0)
        result = 31 * result + status.hashCode()
        return result
    }
}