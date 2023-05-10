package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString


/**
 * From [ARIES RFC 0453](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2)
 */
@Serializable
@SerialName(SchemaIndex.MSG_ISSUE_CRED_REQUEST)
class RequestCredential : JsonWebMessage {

    @SerialName("body")
    val body: RequestCredentialBody

    constructor(
        body: RequestCredentialBody,
        parentThreadId: String? = null,
        attachment: JwmAttachment
    ) : super(
        type = SchemaIndex.MSG_ISSUE_CRED_REQUEST,
        parentThreadId = parentThreadId,
        threadId = uuid4().toString(),
        attachments = arrayOf(attachment)
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "RequestCredential(body=$body)"
    }

}