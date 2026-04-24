package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class AssociatedBodyInformationExtension(
    val dummy: Unit? = null,
) {
    object SerialNames {
        // none have been defined so far
    }
}