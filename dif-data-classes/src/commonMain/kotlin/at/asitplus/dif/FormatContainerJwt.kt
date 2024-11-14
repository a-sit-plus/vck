package at.asitplus.dif

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class FormatContainerJwt(
    @SerialName("alg")
    val algorithmStrings: Collection<String>? = null,
) {
    @Transient
    val algorithms: Set<JsonWebAlgorithm>? = algorithmStrings
        ?.mapNotNull { s -> JsonWebAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()

}