package at.asitplus.wallet.lib.dcapi.request

import at.asitplus.catching
import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.Serializable

@Serializable
data class Oid4vpDCAPIRequest(
    // openid4vp-v<version>-<request-type>
    val protocol: String,
    val request: String,
    val credentialId: Int,
    val callingPackageName: String?,
    val callingOrigin: String, // TODO test with requester that is an Android app
) : DCAPIRequest() {
    init {
        require(callingOrigin != null || callingPackageName != null)
        require((protocol.startsWith(OID4VP_PREFIX) && protocol.count { it == DELIMITER } == 2)
                || protocol == "openid4vp") // legacy beahaviour
        getOpenIdVersion().getOrNull()?.let { require(it == "1") }
    }

    fun getOpenIdVersion() =
        catching { protocol.removePrefix(OID4VP_PREFIX).split(DELIMITER).first() }

    fun getRequestType() =
        catching { protocol.removePrefix(OID4VP_PREFIX).split(DELIMITER)[1] }

    fun isSignedRequest() =
        catching {
            getRequestType().getOrThrow().let { it == "signed" || it == "multisigned" }
        }.getOrElse { false }

    override fun serialize(): String = vckJsonSerializer.encodeToString(this)

    companion object {
        private const val OID4VP_PREFIX = "openid4vp-v"
        private const val DELIMITER = '-'
        fun deserialize(input: String) =
            catching { vckJsonSerializer.decodeFromString<Oid4vpDCAPIRequest>(input) }
    }
}
