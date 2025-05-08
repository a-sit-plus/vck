package at.asitplus.wallet.lib.dcapi.request

import at.asitplus.catching
import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.Serializable

@Serializable
data class PreviewDCAPIRequest(
    val request: String,
    // namespace -> name, intentToRetain
    val requestedData: MutableMap<String, MutableList<Pair<String, Boolean>>>,
    val credentialId: Int,
    val callingPackageName: String? = null,
    val callingOrigin: String? = null,
    val nonce: ByteArray,
    val readerPublicKeyBase64: String,
    val docType: String,
) : DCAPIRequest() {
    init {
        require(callingOrigin != null || callingPackageName != null)
    }

    override fun serialize(): String = vckJsonSerializer.encodeToString(this)

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


    companion object {
        fun deserialize(input: String) =
            catching { vckJsonSerializer.decodeFromString<PreviewDCAPIRequest>(input) }
    }
}