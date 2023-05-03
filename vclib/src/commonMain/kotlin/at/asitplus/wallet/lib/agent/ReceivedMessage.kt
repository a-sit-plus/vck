package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.msg.JsonWebMessage

sealed class ReceivedMessage {
    data class Success(
        val body: JsonWebMessage,
        @Deprecated(message = "Use `senderKey` instead")
        val senderKeyId: String? = null,
        val senderKey: JsonWebKey? = null,
    ) : ReceivedMessage()

    object Error : ReceivedMessage()
}
