package at.asitplus.wallet.lib.msg

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
@Serializable
data class ProblemReportBody(
    @SerialName("code")
    val code: String,
    @SerialName("comment")
    val comment: String? = null,
    @SerialName("args")
    val args: Array<String>? = null,
    @SerialName("escalate_to")
    val escalateTo: String? = null,
) {
    constructor(
        sorter: ProblemReportSorter,
        scope: ProblemReportScope,
        descriptor: ProblemReportDescriptor,
        details: String,
        comment: String? = null,
        args: Array<String> = arrayOf()
    ) : this(
        code = "${sorter.code}.${scope.code}.${descriptor.code}.$details",
        comment = comment,
        args = args,
        escalateTo = null
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as ProblemReportBody

        if (code != other.code) return false
        if (comment != other.comment) return false
        if (args != null) {
            if (other.args == null) return false
            if (!args.contentEquals(other.args)) return false
        } else if (other.args != null) return false
        if (escalateTo != other.escalateTo) return false

        return true
    }

    override fun hashCode(): Int {
        var result = code.hashCode()
        result = 31 * result + (comment?.hashCode() ?: 0)
        result = 31 * result + (args?.contentHashCode() ?: 0)
        result = 31 * result + (escalateTo?.hashCode() ?: 0)
        return result
    }

}