package at.asitplus.wallet.lib.msg

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec)
 */
enum class ProblemReportDescriptor(val code: String) {
    TRUST("trust"),
    TRANSPORT("xfer"),
    DID("did"),
    MESSAGE("msg"),
    INTERNAL("me"),
    REQUIREMENTS("req"),
    LEGAL("legal");

    companion object {
        fun parseCode(code: String) = values().firstOrNull { it.code == code }
    }
}