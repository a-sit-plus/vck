package at.asitplus.wallet.lib.msg

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
enum class ProblemReportSorter(val code: String) {
    ERROR("e"),
    WARNING("w");

    companion object {
        fun parseCode(code: String) = values().firstOrNull { it.code == code }
    }
}