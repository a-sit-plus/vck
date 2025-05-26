package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@ConsistentCopyVisibility
@Serializable
data class DCAPIResponse private constructor(
    // ISO 18013-7 Annex-C:
    // response: Base64EncryptedResponse contains the cbor encoded EncryptedResponse as a
    // base64-url-without-padding string
    @SerialName("response")
    val response: String
) {
    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        @OptIn(ExperimentalEncodingApi::class)
        fun createIsoMdocResponse(response: EncryptedResponse): DCAPIResponse =
            DCAPIResponse(
                Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
                    .encode(response.serialize())
            )

        fun createOid4vpResponse(response: String): DCAPIResponse =
            DCAPIResponse(response)
    }
}
