package at.asitplus.wallet.lib.aries

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.msg.JsonWebMessage


sealed class InternalNextMessage {

    data class Finished(
        val lastMessage: JsonWebMessage
    ) : InternalNextMessage()

    data class SendAndWrap(
        val message: JsonWebMessage,
        val senderKey: JsonWebKey? = null,
        val endpoint: String? = null
    ) : InternalNextMessage()

    data class IncorrectState(
        val reason: String
    ) : InternalNextMessage()

    data class SendProblemReport(
        val message: JsonWebMessage,
        val senderKey: JsonWebKey? = null,
        val endpoint: String? = null
    ) : InternalNextMessage()
}

