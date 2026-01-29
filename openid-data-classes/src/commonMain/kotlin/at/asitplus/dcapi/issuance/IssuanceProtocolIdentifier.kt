package at.asitplus.dcapi.issuance

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class IssuanceProtocolIdentifier(
    val protocol: String
) {
    private fun checkOpenId4VciProtocolIdentifier() {
        val isOpenId4VciDashed =
            protocol.startsWith(PART_OPENID4VCI) && protocol.count { it == DELIMITER } == 1
        val versionDashed = protocol.removePrefix(PART_OPENID4VCI).removePrefix("$DELIMITER")

        val isOpenId4VciLegacy = protocol.startsWith(PART_OPENID4VCI) && protocol.count { it == DELIMITER } == 0
        val versionLegacy = protocol.removePrefix(PART_OPENID4VCI)

        require(isOpenId4VciDashed || isOpenId4VciLegacy) { "Unsupported issuance protocol: $protocol" }
        val version = if (isOpenId4VciDashed) versionDashed else versionLegacy
        require(version == PART_V1 || version == PART_V1_LEGACY) {
            "Only version 1 is supported, got $version"
        }
    }

    init {
        checkOpenId4VciProtocolIdentifier()
    }

    companion object {
        private const val DELIMITER = '-'

        /** `openid4vci` */
        private const val PART_OPENID4VCI = "openid4vci"

        /** `v1` */
        private const val PART_V1 = "v1"

        /** `1.0` */
        private const val PART_V1_LEGACY = "1.0"

        /** `openid4vci-v1` */
        val OPENID4VCI_V1 = IssuanceProtocolIdentifier("$PART_OPENID4VCI$DELIMITER$PART_V1")

        /** `openid4vci1.0` */
        val OPENID4VCI_V1_LEGACY = IssuanceProtocolIdentifier("$PART_OPENID4VCI$PART_V1_LEGACY")
    }
}
