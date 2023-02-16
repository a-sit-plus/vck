package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * From [ARIES RFC 0454](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2)
 */
@Serializable
data class PresentationBody(
    @SerialName("comment")
    val comment: String,
    @SerialName("formats")
    val formats: Array<AttachmentFormatReference>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as PresentationBody

        if (comment != other.comment) return false
        if (!formats.contentEquals(other.formats)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = comment.hashCode()
        result = 31 * result + formats.contentHashCode()
        return result
    }
}