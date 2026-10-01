package at.asitplus.iso

import io.github.z4kn4fein.semver.Version
import io.github.z4kn4fein.semver.toVersion
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2026 standard: Mdoc response (10.3)
 */
@Serializable
data class DeviceResponse(
    @SerialName("version")
    @Serializable(with = IsoVersionSerializer::class)
    val parsedVersion: Version,
    @SerialName("documents")
    val documents: Array<Document>? = null,
    @SerialName("zkDocuments")
    val zkDocuments: Array<ZkDocument>? = null,
    @SerialName("encryptedDocuments")
    val encryptedDocuments: Array<EncryptedDocuments>? = null,
    @SerialName("documentErrors")
    val documentErrors: Array<Map<String, Int>>? = null,
    @SerialName("status")
    val status: UInt,
) {

    @Deprecated("Use constructor with parsedVersion")
    constructor(
        version: String,
        documents: Array<Document>? = null,
        zkDocuments: Array<ZkDocument>? = null,
        encryptedDocuments: Array<EncryptedDocuments>? = null,
        documentErrors: Array<Map<String, Int>>? = null,
        status: UInt,
    ): this(
        parsedVersion = version.toVersion(strict = false),
        documents = documents,
        zkDocuments = zkDocuments,
        encryptedDocuments = encryptedDocuments,
        documentErrors = documentErrors,
        status = status,
    )

    @Deprecated("Use parsedVersion instead", ReplaceWith("parsedVersion.toIsoString()"))
    val version: String
        get() = parsedVersion.toIsoString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceResponse

        if (parsedVersion != other.parsedVersion) return false
        if (documents != null) {
            if (other.documents == null) return false
            if (!documents.contentEquals(other.documents)) return false
        } else if (other.documents != null) return false
        if (zkDocuments != null) {
            if (other.zkDocuments == null) return false
            if (!zkDocuments.contentEquals(other.zkDocuments)) return false
        } else if (other.zkDocuments != null) return false
        if (encryptedDocuments != null) {
            if (other.encryptedDocuments == null) return false
            if (!encryptedDocuments.contentEquals(other.encryptedDocuments)) return false
        } else if (other.encryptedDocuments != null) return false
        if (documentErrors != null) {
            if (other.documentErrors == null) return false
            if (!documentErrors.contentEquals(other.documentErrors)) return false
        } else if (other.documentErrors != null) return false
        return status == other.status
    }

    override fun hashCode(): Int {
        var result = parsedVersion.hashCode()
        result = 31 * result + (documents?.contentHashCode() ?: 0)
        result = 31 * result + (zkDocuments?.contentHashCode() ?: 0)
        result = 31 * result + (encryptedDocuments?.contentHashCode() ?: 0)
        result = 31 * result + (documentErrors?.contentHashCode() ?: 0)
        result = 31 * result + status.hashCode()
        return result
    }
}
