package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.SchemaIndex
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

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
        threadId = uuid4().toString(),
    ) {
        this.body = body
    }

    override fun serialize() = jsonSerializer.encodeToString(this)

    override fun toString(): String {
        return "ProblemReport(parentThreadId='$parentThreadId', body=$body)"
    }

}