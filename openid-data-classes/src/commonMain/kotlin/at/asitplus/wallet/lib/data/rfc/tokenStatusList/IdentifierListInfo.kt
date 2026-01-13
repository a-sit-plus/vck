package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
@SerialName("identifier_list")
data class IdentifierListInfo(
    @SerialName("id")
    @ByteString
    val identifier: ByteArray,
    @SerialName("uri")
    override val uri: UniformResourceIdentifier,
    @SerialName("certificate")
    @ByteString
    override val certificate: ByteArray? = null,
) : RevocationListInfo() {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IdentifierListInfo

        if (!identifier.contentEquals(other.identifier)) return false
        if (uri != other.uri) return false
        if (certificate != null) {
            if (other.certificate == null) return false
            if (!certificate.contentEquals(other.certificate)) return false
        } else if (other.certificate != null) {
            return false
        }

        return true
    }

    override fun hashCode(): Int {
        var result = identifier.contentHashCode()
        result = 31 * result + uri.hashCode()
        result = 31 * result + (certificate?.contentHashCode() ?: 0)
        return result
    }
}
