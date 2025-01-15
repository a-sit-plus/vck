package at.asitplus.dif

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition),
 * adapted for [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html#appendix-B.4.2)
 */
@Serializable
data class FormatContainerSdJwt(
    @Deprecated("Use other properties in this class")
    @SerialName("alg")
    val algorithmStrings: Collection<String>? = null,
    @SerialName("sd-jwt_alg_values")
    val sdJwtAlgorithmStrings: Set<String>? = null,
    @SerialName("kb-jwt_alg_values")
    val kbJwtAlgorithmStrings: Set<String>? = null,
) {
    @Deprecated("Use other properties in this class")
    @Transient
    val algorithms: Set<JsonWebAlgorithm>? = algorithmStrings
        ?.mapNotNull { s -> JsonWebAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()

    @Transient
    val sdJwtAlgorithms: Set<JwsAlgorithm>? = sdJwtAlgorithmStrings
        ?.mapNotNull { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()

    @Transient
    val kbJwtAlgorithms: Set<JwsAlgorithm>? = kbJwtAlgorithmStrings
        ?.mapNotNull { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()


}