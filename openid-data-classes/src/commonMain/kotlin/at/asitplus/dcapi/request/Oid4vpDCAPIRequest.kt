package at.asitplus.dcapi.request

import at.asitplus.catchingUnwrapped
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
    val callingOrigin: String,
) : DCAPIRequest() {
    val openIdVersion = catchingUnwrapped {
        protocol.removePrefix(OPENID4VP).split(DELIMITER)[1]
    }.getOrNull()

    val requestType = catchingUnwrapped {
        protocol.removePrefix(OPENID4VP).split(DELIMITER)[2]
    }.getOrNull()

    val isSignedRequest = catchingUnwrapped {
        requestType?.let { it == SIGNED || it == MULTISIGNED }
    }.getOrElse { false }

    init {
        val openId4vpFinal = protocol.startsWith(OPENID4VP) && protocol.count { it == DELIMITER } == 2
        require(openId4vpFinal || protocol == OPENID4VP /* draft 24*/)
        require(openIdVersion == "v1" || openIdVersion == null /* draft 24*/)
        require(requestType != MULTISIGNED) { "multisigned not supported" }
        requestType?.let { require(it == UNSIGNED || it == SIGNED) }
    }

    companion object {
        private const val DELIMITER = '-'

        /** `openid4vp` */
        const val OPENID4VP = "openid4vp"

        /** `multisigned` */
        const val MULTISIGNED = "multisigned"

        /** `signed` */
        const val SIGNED = "signed"

        /** `unsigned` */
        const val UNSIGNED = "unsigned"
    }
}
