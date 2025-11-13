package at.asitplus.dif

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
    @SerialName("dc+sd-jwt")
    val sdJwt: FormatContainerSdJwt? = null,
    @SerialName("ldp")
    val ldp: FormatContainerLdp? = null,
    @SerialName("ldp_vp")
    val ldpVp: FormatContainerLdp? = null,
    @SerialName("ldp_vc")
    val ldpVc: FormatContainerLdp? = null,
    @SerialName("mso_mdoc")
    val msoMdoc: FormatContainerJwt? = null,
)
