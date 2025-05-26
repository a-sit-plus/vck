package at.asitplus.wallet.lib.dcapi.request

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
    init {
        require((protocol.startsWith(DC_API_OID4VP_PROTOCOL_IDENTIFIER) && protocol.count { it == DELIMITER } == 2))
        require(getOpenIdVersion().getOrNull() == "v1")
        if (getRequestType().getOrNull() == "multisigned") {
            throw InvalidRequest("multisigned not supported")
        }
        getRequestType().getOrNull().let { require(it == "unsigned" || it == "signed") }
    }

    fun getOpenIdVersion() =
        catching { protocol.removePrefix(DC_API_OID4VP_PROTOCOL_IDENTIFIER).split(DELIMITER)[1] }

    fun getRequestType() =
        catching { protocol.removePrefix(DC_API_OID4VP_PROTOCOL_IDENTIFIER).split(DELIMITER)[2] }

    fun isSignedRequest() =
        catching {
            getRequestType().getOrNull().let { it == "signed" || it == "multisigned" }
        }.getOrElse { false }

    override fun serialize(): String = vckJsonSerializer.encodeToString(this)

    companion object {
        private const val DELIMITER = '-'
        fun deserialize(input: String) =
            catching { vckJsonSerializer.decodeFromString<Oid4vpDCAPIRequest>(input) }
    }
}
