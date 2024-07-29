package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * From [ARIES RFC 0454](https://github.com/hyperledger/aries-rfcs/blob/main/features/0454-present-proof-v2)
 */
@Serializable
@SerialName(SchemaIndex.MSG_PRESENT_PROOF_REQUEST)
class RequestPresentation : JsonWebMessage {

    @SerialName("body")
    val body: RequestPresentationBody

    constructor(
        body: RequestPresentationBody,
        parentThreadId: String? = null,
        attachment: JwmAttachment
    ) : super(
        type = SchemaIndex.MSG_PRESENT_PROOF_REQUEST,
        parentThreadId = parentThreadId,
        threadId = uuid4().toString(),
        attachments = arrayOf(attachment)
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "RequestPresentation(body=$body)"
    }

}