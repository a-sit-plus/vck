package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents a configuration and metadata abstraction for a Zero-Knowledge proving system
 * used in ISO mDoc presentation requests.
 */
@Serializable(with = ZkSystemSpecSerializer::class)
data class ZkSystemSpec (
    /**
     * A unique identifier for this specific ZK system configuration instance within a request.
     */
    @SerialName(PROP_ZK_SYSTEM_ID)
    val id: String,

    /**
     * The name or identifier of the underlying ZK system or proving scheme
     * (e.g., the backend family).
     */
    @SerialName(PROP_SYSTEM)
    val system: String,

    /**
     * Protocol- or circuit-specific parameters required by the ZK system
     * (e.g., circuit hashes, attribute counts, or versioning parameters).
     */
    @SerialName(PROP_PARAMS)
    val params: Map<String, Any>
) {
    companion object {
        const val PROP_ZK_SYSTEM_ID = "zkSystemId"
        const val PROP_SYSTEM = "system"
        const val PROP_PARAMS = "params"
    }
}
