package at.asitplus.iso

import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc response (8.3.2.2.2.2)
 */
@Serializable
data class ServerResponse(
    @SerialName("version")
    val version: String,
    @SerialName("documents")
    val documentsJws: Array<@Serializable(JwsCompactStringSerializer::class) JwsCompact>,
    @SerialName("documentErrors")
    val documentErrors: Map<String, Int>? = null,
) {
    @Transient
    @Deprecated("Please use documentsJws instead", ReplaceWith("documentsJws"))
    val documents = documentsJws.map { it.toString() }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ServerResponse

        if (version != other.version) return false
        if (!documentsJws.contentEquals(other.documentsJws)) return false
        return documentErrors == other.documentErrors
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + documentsJws.contentHashCode()
        result = 31 * result + (documentErrors?.hashCode() ?: 0)
        return result
    }

}