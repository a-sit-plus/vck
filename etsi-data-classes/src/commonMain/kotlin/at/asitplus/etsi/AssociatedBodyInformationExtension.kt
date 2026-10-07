package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class AssociatedBodyInformationExtension(
    /**
     * Implementation placeholder for currently unmodelled associated-body extension content; not an ETSI-defined
     * field.
     */
    val dummy: Unit? = null,
) {
    object SerialNames {
        // none have been defined so far
    }
}