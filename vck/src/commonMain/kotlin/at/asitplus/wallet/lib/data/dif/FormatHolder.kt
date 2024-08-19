package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.data.ConstantIndex
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class FormatHolder(
    @SerialName("jwt")
    val jwt: FormatContainerJwt? = null,
    @SerialName("jwt_vp")
    val jwtVp: FormatContainerJwt? = null,
    @SerialName("jwt_vc")
    val jwtVc: FormatContainerJwt? = null,
    /**
     * Deprecated, unofficial value, please use [jwtSd]
     */
    @SerialName("jwt_sd")
    val jwtSdDeprecated: FormatContainerJwt? = null,
    @SerialName("vc+sd-jwt")
    val jwtSd: FormatContainerJwt? = null,
    @SerialName("ldp")
    val ldp: FormatContainerLdp? = null,
    @SerialName("ldp_vp")
    val ldpVp: FormatContainerLdp? = null,
    @SerialName("ldp_vc")
    val ldpVc: FormatContainerLdp? = null,
    @SerialName("mso_mdoc")
    val msoMdoc: FormatContainerJwt? = null,
) {
    /**
     * Inverse operation to `ConstantIndex.CredentialRepresentation.toFormatHolder()`
     */
    fun toSetOfRepresentation(): Set<ConstantIndex.CredentialRepresentation> =
        mutableSetOf<ConstantIndex.CredentialRepresentation>().apply {
            if (jwt != null) add(ConstantIndex.CredentialRepresentation.PLAIN_JWT)
            if (jwtSd != null) add(ConstantIndex.CredentialRepresentation.SD_JWT)
            if (msoMdoc != null) add(ConstantIndex.CredentialRepresentation.ISO_MDOC)
        }.toSet()
}