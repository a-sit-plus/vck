package at.asitplus.wallet.lib.msg

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
enum class ProblemReportScope(val code: String) {
    PROTOCOL("p"),
    MESSAGE("m");

    companion object {
        fun parseCode(code: String) = values().firstOrNull { it.code == code }
    }
}