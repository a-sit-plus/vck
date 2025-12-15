package at.asitplus.openid

import kotlinx.serialization.Serializable

@Serializable(with = CredentialFormatSerializer::class)
enum class CredentialFormatEnum(val text: String) {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    DC_SD_JWT("dc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc"), ;

    companion object {
        fun parse(text: String): CredentialFormatEnum? =
            when (text) {
                "mso_mdoc_zk" -> MSO_MDOC // Alias for DCQLQuery with "mso_mdoc_zk" format
                else -> entries.firstOrNull { it.text == text }
            }
    }
}