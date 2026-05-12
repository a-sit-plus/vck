package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class SdJwtTypeMetadata16(
    @SerialName(SerialNames.VCT)
    val vct: String,
    @SerialName(SerialNames.NAME)
    val name: String? = null,
    @SerialName(SerialNames.DESCRIPTION)
    val description: String? = null,
    @SerialName(SerialNames.DISPLAY)
    val display: List<JsonElement>? = null,
    @SerialName(SerialNames.CLAIMS)
    val claims: List<JsonElement>? = null,
) {
    object SerialNames {
        const val VCT = "vct"
        const val NAME = "name"
        const val DESCRIPTION = "description"
        const val DISPLAY = "display"
        const val CLAIMS = "claims"
    }
}