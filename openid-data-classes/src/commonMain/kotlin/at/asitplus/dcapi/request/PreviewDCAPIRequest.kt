package at.asitplus.dcapi.request

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
@Deprecated(
    "Legacy preview protocol. Use OID4VP or ISO 18013-7 Annex C",
    replaceWith = ReplaceWith("Oid4vpDCAPIRequest or IsoMdocRequest")
)
data class PreviewDCAPIRequest(
    @SerialName("request")
    val request: String,
    // namespace -> name, intentToRetain
    @SerialName("requestedData")
    val requestedData: MutableMap<String, MutableList<Pair<String, Boolean>>>,
    @SerialName("credentialId")
    val credentialId: String,
    @SerialName("callingPackageName")
    val callingPackageName: String? = null,
    @SerialName("callingOrigin")
    val callingOrigin: String? = null,
    @SerialName("nonce")
    val nonce: ByteArray,
    @SerialName("readerPublicKeyBase64")
    val readerPublicKeyBase64: String,
    @SerialName("docType")
    val docType: String,
) : DCAPIRequest() {
    init {
        require(callingOrigin != null || callingPackageName != null)
    }

    @Suppress("DEPRECATION")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PreviewDCAPIRequest

        if (request != other.request) return false
        if (requestedData != other.requestedData) return false
        if (credentialId != other.credentialId) return false
        if (callingPackageName != other.callingPackageName) return false
        if (callingOrigin != other.callingOrigin) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (readerPublicKeyBase64 != other.readerPublicKeyBase64) return false
        if (docType != other.docType) return false

        return true
    }

    override fun hashCode(): Int {
        var result = request.hashCode()
        result = 31 * result + requestedData.hashCode()
        result = 31 * result + credentialId.hashCode()
        result = 31 * result + (callingPackageName?.hashCode() ?: 0)
        result = 31 * result + (callingOrigin?.hashCode() ?: 0)
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + readerPublicKeyBase64.hashCode()
        result = 31 * result + docType.hashCode()
        return result
    }
}