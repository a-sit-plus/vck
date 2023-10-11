package at.asitplus.wallet.lib.aries

import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.wallet.lib.msg.JsonWebMessage

sealed class ReceivedMessage {
    data class Success(
        val body: JsonWebMessage,
        val senderKey: JsonWebKey? = null,
    ) : ReceivedMessage()

    object Error : ReceivedMessage()
}
