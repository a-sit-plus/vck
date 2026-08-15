package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2026 standard: ZKP Mdoc request (10.2.4)
 */
@Serializable
data class ZkRequest (
    @SerialName("zkRequired")
    val zkRequired: Boolean,
    @SerialName("systemSpecs")
    val systemSpecs: List<ZkSystemSpec>,
) {
    init {
        validate()
    }

    private fun validate() {
        require(!zkRequired || systemSpecs.isNotEmpty()) {
            "systemSpecs list cannot be empty if Zero-Knowledge is enforced"
        }
        val ids = systemSpecs.map { it.id }
        require(ids.size == ids.distinct().size) {
            "ZkSystemType IDs are not unique!"
        }
    }
}
