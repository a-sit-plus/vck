package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc request (8.3.2.2.2.1)
 */
@Serializable
data class ServerRequest(
    @SerialName("version")
    val version: String,
    @SerialName("token")
    val token: String,
    @SerialName("docRequests")
    val docRequests: Array<ServerItemsRequest>,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ServerRequest

        if (version != other.version) return false
        return docRequests.contentEquals(other.docRequests)
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + docRequests.contentHashCode()
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<ServerRequest>(it)
        }.wrap()
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc request (8.3.2.2.2.1)
 */
@Serializable
data class ServerItemsRequest(
    @SerialName("docType")
    val docType: String,
    @SerialName("nameSpaces")
    val namespaces: Map<String, Map<String, Boolean>>,
    @SerialName("requestInfo")
    val requestInfo: Map<String, String>? = null,
)

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for Server retrieval mdoc response (8.3.2.2.2.2)
 */
@Serializable
data class ServerResponse(
    @SerialName("version")
    val version: String,
    /**
     * A single document is a [JwsSigned], whose payload is a [MobileDrivingLicenceJws]
     */
    @SerialName("documents")
    val documents: Array<String>,
    @SerialName("documentErrors")
    val documentErrors: Map<String, Int>? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

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

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<ServerResponse>(it)
        }.wrap()
    }
}
