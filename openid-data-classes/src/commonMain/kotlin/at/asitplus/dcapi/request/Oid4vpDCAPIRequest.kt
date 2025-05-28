package at.asitplus.dcapi.request

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.DC_API_OID4VP_PROTOCOL_IDENTIFIER
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Oid4vpDCAPIRequest(
    // openid4vp-v<version>-<request-type>
    @SerialName("protocol")
    val protocol: String,
    @SerialName("request")
    val request: String,
    @SerialName("credentialId")
    val credentialId: String,
    @SerialName("callingPackageName")
    val callingPackageName: String,
    @SerialName("callingOrigin")
    val callingOrigin: String
) : DCAPIRequest() {
    val openIdVersion =
        catching {
            protocol.removePrefix(DC_API_OID4VP_PROTOCOL_IDENTIFIER).split(DELIMITER)[1]
        }.getOrNull()

    val requestType =
        catching {
            protocol.removePrefix(DC_API_OID4VP_PROTOCOL_IDENTIFIER).split(DELIMITER)[2]
        }.getOrNull()

    val isSignedRequest =
        catching {
            requestType?.let { it == "signed" || it == "multisigned" }
        }.getOrElse { false }

    init {
        require((protocol.startsWith(DC_API_OID4VP_PROTOCOL_IDENTIFIER) && protocol.count { it == DELIMITER } == 2))
        require(openIdVersion == "v1")
        if (requestType == "multisigned") {
            throw IllegalArgumentException("multisigned not supported")
        }
        requestType?.let { require(it == "unsigned" || it == "signed") }
    }

    companion object {
        private const val DELIMITER = '-'
    }
}
