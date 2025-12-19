package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkRequest (
    @SerialName("ZkRequired")
    val zkRequired: Boolean,
    @SerialName("systemSpecs")
    val systemSpecs: List<ZkSystemSpec>,
) {
    fun validate() {
        require(!zkRequired || systemSpecs.isNotEmpty()) {
            "systemSpecs list cannot be empty if Zero-Knowledge is enforced"
        }
    }
    companion object {
        val Default = ZkRequest(false, emptyList())
    }
}