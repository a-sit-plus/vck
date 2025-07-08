package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.data.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

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
        threadId = @OptIn(ExperimentalUuidApi::class) Uuid.random().toString(),
        attachments = arrayOf(attachment)
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "RequestCredential(body=$body)"
    }

}

