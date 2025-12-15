package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkRequest (
    @SerialName("ZkRequired")
    val zkRequired: Boolean,
    @SerialName("systemSpecs")
    val systemSpecs: List<ZkSystemSpec>,
)