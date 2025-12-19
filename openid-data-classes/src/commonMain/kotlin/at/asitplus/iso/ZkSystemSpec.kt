package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable(with = ZkSystemSpecSerializer::class)
data class ZkSystemSpec (
    @SerialName(PROP_ZK_SYSTEM_ID)
    val zkSystemId: String,
    @SerialName(PROP_SYSTEM)
    val system: String,
    @SerialName(PROP_PARAMS)
    val params: Map<String, Any>
) {


    companion object {
        const val PROP_ZK_SYSTEM_ID = "zkSystemId"
        const val PROP_SYSTEM = "system"
        const val PROP_PARAMS = "params"
    }
}
