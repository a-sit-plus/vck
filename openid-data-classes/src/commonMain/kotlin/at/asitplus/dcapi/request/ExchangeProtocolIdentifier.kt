package at.asitplus.dcapi.request

import at.asitplus.catchingUnwrapped
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ExchangeProtocolIdentifier(
    val protocol: String
) {

    val openIdVersion
        get() = catchingUnwrapped {
            protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[1]
        }.getOrNull()

    // TODO handle iso mdoc here:
    val requestType
        get() = catchingUnwrapped {
            protocol.removePrefix(PART_OPENID4VP).split(DELIMITER)[2]
        }.getOrNull()

    val isSignedOpenId4VpRequest: Boolean
        get() = requestType?.let { it == PART_SIGNED || it == PART_MULTISIGNED } == true

    val isUnsignedOpenId4VpRequest: Boolean
        get() = requestType?.let { it == PART_UNSIGNED } == true

    private fun checkOpenId4VpProtocolIdentifier() {
        val openId4vpFinal = protocol.startsWith(PART_OPENID4VP) && protocol.count { it == DELIMITER } == 2
        require(openId4vpFinal || protocol == PART_OPENID4VP /* draft 24*/)
        require(openIdVersion == PART_V1 || openIdVersion == null /* draft 24*/) {
            "Only version 1 is supported, got $openIdVersion"
        }
        require(requestType != PART_MULTISIGNED) { "multisigned not supported" }
        requestType?.let {
            require(it == PART_UNSIGNED || it == PART_SIGNED) {
                "Request type must be one of: unsigned, signed"
            }
        }
    }

    init {
        if (protocol != PROTOCOL_ISO_MDOC_ANNEX_C) {
            checkOpenId4VpProtocolIdentifier()
        }
    }

    enum class RequestType {
        UNSIGNED, SIGNED, MULTISIGNED
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
        val PROTOCOL_V1_UNSIGNED = ExchangeProtocolIdentifier("$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_UNSIGNED")

        /** `openid4vp-v1-signed` */
        val PROTOCOL_V1_SIGNED = ExchangeProtocolIdentifier("$PART_OPENID4VP$DELIMITER$PART_V1$DELIMITER$PART_SIGNED")

        const val PROTOCOL_ISO_MDOC_ANNEX_C = "org-iso-mdoc"
    }
}