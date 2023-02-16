package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.msg.JsonWebMessage

sealed class ReceivedMessage {
    data class Success(val body: JsonWebMessage, val senderKeyId: String?) : ReceivedMessage()
    object Error : ReceivedMessage()
}
