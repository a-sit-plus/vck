package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.vckJsonSerializer
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

    fun serialize() = vckJsonSerializer.encodeToString(this)

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
            vckJsonSerializer.decodeFromString<ServerRequest>(it)
        }.wrap()
    }
}

