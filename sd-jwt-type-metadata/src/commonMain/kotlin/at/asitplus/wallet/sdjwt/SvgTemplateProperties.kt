package at.asitplus.wallet.sdjwt

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SvgTemplateProperties(
    @SerialName(SerialNames.ORIENTATION)
    val imageOrientation: SvgTemplatePropertyImageOrientation? = null,
    @SerialName(SerialNames.COLOR_SCHEME)
    val colorScheme: SvgTemplatePropertyColorScheme? = null,
    @SerialName(SerialNames.CONTRAST)
    val contrast: SvgTemplatePropertyContrast? = null,
) {
    object SerialNames {
        const val ORIENTATION = "orientation"
        const val COLOR_SCHEME = "color_scheme"
        const val CONTRAST = "contrast"
    }
}