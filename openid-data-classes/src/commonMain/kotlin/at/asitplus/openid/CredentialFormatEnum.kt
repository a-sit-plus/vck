package at.asitplus.openid

import at.asitplus.openid.CredentialFormatEnum.entries
import kotlinx.serialization.Serializable

@Serializable(with = CredentialFormatSerializer::class)
enum class CredentialFormatEnum(val text: String) {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    @Deprecated("Deprecated in SD-JWT VC since draft 06", replaceWith = ReplaceWith("DC_SD_JWT"))
    VC_SD_JWT("vc+sd-jwt"),
    DC_SD_JWT("dc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    fun coerce() = if(this == VC_SD_JWT) DC_SD_JWT else this

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}