package at.asitplus.dcapi.request

import at.asitplus.catchingUnwrapped
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class Oid4vpDCAPIRequest(
    /** Format `openid4vp-v<version>-<request-type>`, see [PROTOCOL_V1_SIGNED]. */
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
        protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[1]
    }.getOrNull()

    val requestType = catchingUnwrapped {
        protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[2]
    }.getOrNull()

    val isSignedRequest = catchingUnwrapped {
        requestType?.let { it == PART_SIGNED || it == PART_MULTISIGNED }
    }.getOrElse { false }

    init {
        val openId4vpFinal = protocol.startsWith(PART_OPENID4VP) && protocol.count { it == DELIMITER } == 2
        require(openId4vpFinal || protocol == PART_OPENID4VP /* draft 24*/)
        require(openIdVersion == PART_V1 || openIdVersion == null /* draft 24*/)
        require(requestType != PART_MULTISIGNED) { "multisigned not supported" }
        requestType?.let { require(it == PART_UNSIGNED || it == PART_SIGNED) }
    }

    companion object {
        private const val DELIMITER = '-'

        /** `openid4vp` */
        const val PART_OPENID4VP = "openid4vp"

        /** `v1` */
        const val PART_V1 = "v1"

        /** `multisigned` */
        const val PART_MULTISIGNED = "multisigned"

        /** `signed` */
        const val PART_SIGNED = "signed"

        /** `unsigned` */
        const val PART_UNSIGNED = "unsigned"

        /** `openid4vp-v1-unsigned` */
        const val PROTOCOL_V1_UNSIGNED = "$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_UNSIGNED"

        /** `openid4vp-v1-signed` */
        const val PROTOCOL_V1_SIGNED = "$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_SIGNED"
    }
}
