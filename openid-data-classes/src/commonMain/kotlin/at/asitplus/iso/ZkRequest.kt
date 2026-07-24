package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2026 standard: ZKP Mdoc request (10.2.4)
 */
@Serializable
data class ZkRequest (
    @SerialName("zkRequired")
    override val zkRequired: Boolean,
    @SerialName("systemSpecs")
    override val systemSpecs: List<ZkSystemSpec>,
): ZkInfo
