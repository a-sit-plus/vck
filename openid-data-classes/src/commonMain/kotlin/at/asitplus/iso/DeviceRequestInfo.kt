package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional device request info (10.2.5)
 */
@Serializable
data class DeviceRequestInfo(
    @SerialName("useCases")
    val useCases: List<UseCase>? = null,
)


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional device request info (10.2.5)
 */
@Serializable
data class UseCase(
    @SerialName("mandatory")
    val mandatory: Boolean,
    @SerialName("documentSets")
    val documentSets: List<List<UInt>>,
    @SerialName("purposeHints")
    val purposeHints: Map<String, Int>? = null,
)
