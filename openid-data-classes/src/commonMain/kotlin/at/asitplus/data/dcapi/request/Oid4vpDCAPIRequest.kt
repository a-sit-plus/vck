package at.asitplus.data.dcapi.request

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.DC_API_OID4VP_PROTOCOL_IDENTIFIER
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import kotlinx.serialization.Serializable

@Serializable
data class Oid4vpDCAPIRequest(
    // openid4vp-v<version>-<request-type>
    val protocol: String,
    val request: String,
    val credentialId: Int,
    val callingPackageName: String,
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
            throw InvalidRequest("multisigned not supported")
        }
        requestType?.let { require(it == "unsigned" || it == "signed") }
    }

    override fun serialize(): String = vckJsonSerializer.encodeToString(this)

    companion object {
        private const val DELIMITER = '-'
        fun deserialize(input: String) =
            catching { vckJsonSerializer.decodeFromString<Oid4vpDCAPIRequest>(input) }
    }
}
