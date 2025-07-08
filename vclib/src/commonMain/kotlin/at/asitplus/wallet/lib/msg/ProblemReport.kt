package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.data.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
@Serializable
@SerialName(SchemaIndex.MSG_PROBLEM_REPORT)
class ProblemReport : JsonWebMessage {

    @SerialName("body")
    val body: ProblemReportBody

    constructor(body: ProblemReportBody, parentThreadId: String? = null) : super(
        type = SchemaIndex.MSG_PROBLEM_REPORT,
        parentThreadId = parentThreadId,
        threadId = @OptIn(ExperimentalUuidApi::class) Uuid.random().toString(),
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "ProblemReport(parentThreadId='$parentThreadId', body=$body)"
    }

}
