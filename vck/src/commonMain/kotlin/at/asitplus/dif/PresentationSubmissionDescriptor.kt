package at.asitplus.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-submission)
 */
@Serializable
data class PresentationSubmissionDescriptor(
    @SerialName("id")
    val id: String,
    @SerialName("format")
    val format: ClaimFormatEnum,
    @SerialName("path")
    val path: String, // JSONPath
    @SerialName("path_nested")
    val nestedPath: PresentationSubmissionDescriptor? = null,
)