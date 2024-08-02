package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Options for [RequestPresentationAttachment]
 */
@Serializable
data class RequestPresentationAttachmentOptions(
    @SerialName("challenge")
    val challenge: String,
    @SerialName("verifier")
    val verifier: String?,
    @SerialName("domain")
    val domain: String? = null
)