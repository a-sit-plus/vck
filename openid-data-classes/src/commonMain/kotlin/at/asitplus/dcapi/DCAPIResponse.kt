package at.asitplus.dcapi

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToByteArray

@ConsistentCopyVisibility
@Serializable
data class DCAPIResponse private constructor(
    /**
     * ISO 18013-7 Annex-C:
     * response: Base64EncryptedResponse contains the cbor encoded EncryptedResponse as a
     * base64-url-without-padding string
     */
    @SerialName("response")
    val response: String,
) {
    companion object {
        fun createIsoMdocResponse(response: EncryptedResponse): DCAPIResponse =
            DCAPIResponse(coseCompliantSerializer.encodeToByteArray(response).encodeToString(Base64UrlStrict))

        fun createOid4vpResponse(response: String): DCAPIResponse =
            DCAPIResponse(response)
    }
}