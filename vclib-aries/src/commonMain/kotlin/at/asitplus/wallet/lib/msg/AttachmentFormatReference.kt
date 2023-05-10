package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
@Serializable
data class AttachmentFormatReference(
    @SerialName("attachment_id")
    val attachmentId: String,
    @SerialName("format")
    val format: String,
)