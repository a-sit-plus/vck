package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * From [ARIES RFC 0453](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2)
 */
@Serializable
@SerialName(SchemaIndex.MSG_ISSUE_CRED_ISSUE)
class IssueCredential : JsonWebMessage {

    @SerialName("body")
    val body: IssueCredentialBody

    constructor(body: IssueCredentialBody, threadId: String, attachments: Array<JwmAttachment>) : super(
        type = SchemaIndex.MSG_ISSUE_CRED_ISSUE,
        threadId = threadId,
        attachments = attachments
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "IssueCredential(body=$body, attachments=${attachments?.contentToString()})"
    }

}