package at.asitplus.openid

import kotlinx.serialization.Serializable

@Serializable(with = CredentialFormatSerializer::class)
enum class CredentialFormatEnum(val text: String) {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    /**
     * Unofficial constant, used by this library prior to implementing OID4VCI Draft 13.
     */
    JWT_VC_SD_UNOFFICIAL("jwt_vc_sd"),
    VC_SD_JWT("vc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}