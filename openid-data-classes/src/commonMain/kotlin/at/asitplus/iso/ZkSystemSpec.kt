package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable(with = ZkSystemSpecSerializer::class)
data class ZkSystemSpec (
    @SerialName(PROP_ZK_SYSTEM_ID)
    override val zkSystemId: String,
    @SerialName(PROP_SYSTEM)
    override val system: String,
    @SerialName(PROP_PARAMS)
    override val params: Map<String, Any>
) : ZkSystem {
    companion object {
        const val PROP_ZK_SYSTEM_ID = "zkSystemId"
        const val PROP_SYSTEM = "system"
        const val PROP_PARAMS = "params"
    }
}
