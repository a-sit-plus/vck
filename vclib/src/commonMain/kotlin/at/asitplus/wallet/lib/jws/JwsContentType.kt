package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JwsContentTypeSerializer::class)
enum class JwsContentType(val text: String) {

    DIDCOMM_PLAIN_JSON("didcomm-plain+json"),
    DIDCOMM_SIGNED_JSON("didcomm-signed+json"),
    DIDCOMM_ENCRYPTED_JSON("didcomm-encrypted+json"),
    JWT("JWT");

}