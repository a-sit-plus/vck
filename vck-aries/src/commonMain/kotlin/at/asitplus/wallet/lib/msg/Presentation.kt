package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * From [ARIES RFC 0454](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2)
 */
@Serializable
@SerialName(SchemaIndex.MSG_PRESENT_PROOF_PRESENTATION)
class Presentation : JsonWebMessage {

    @SerialName("body")
    val body: PresentationBody

    constructor(body: PresentationBody, threadId: String, attachment: JwmAttachment) : super(
        type = SchemaIndex.MSG_PRESENT_PROOF_PRESENTATION,
        threadId = threadId,
        attachments = arrayOf(attachment)
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "Presentation(body=$body, attachments=${attachments?.contentToString()})"
    }

}