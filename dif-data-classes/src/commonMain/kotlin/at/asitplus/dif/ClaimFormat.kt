package at.asitplus.dif

import at.asitplus.dif.ClaimFormat.entries
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable(with = ClaimFormatSerializer::class)
enum class ClaimFormat(val text: String) {
    NONE("none"),
    JWT("jwt"),
    JWT_VC("jwt_vc"),
    JWT_VP("jwt_vp"),
    @Deprecated("Deprecated in SD-JWT VC since draft 06", replaceWith = ReplaceWith("SD_JWT"))
    JWT_SD("vc+sd-jwt"),
    SD_JWT("dc+sd-jwt"),
    LDP("ldp"),
    LDP_VC("ldp_vc"),
    LDP_VP("ldp_vp"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}