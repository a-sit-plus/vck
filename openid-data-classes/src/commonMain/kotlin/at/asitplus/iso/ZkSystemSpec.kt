package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ZkSystemSpec (
    @SerialName("zkSystemId")
    val zkSystemId: String,
    @SerialName("system")
    val system: String,

    // TODO: Fix type! According to ISO/IEC 18013-5:2021 2nd edition, 10.2.7 "params" should be a Map<String, Any>
    //  Implement a custom serializer.
    @SerialName("params")
    val params: Map<String, String>
)
