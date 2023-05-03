package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.msg.JsonWebMessage


/**
 * Use this class for exactly one instance of a protocol run.
 *
 * `T` is the type of the result value of this protocol run.
 */
interface ProtocolStateMachine<T> {

    fun startCreatingInvitation(): InternalNextMessage

    fun startDirect(): InternalNextMessage

    suspend fun parseMessage(body: JsonWebMessage, senderKey: JsonWebKey): InternalNextMessage

    fun getResult(): T?

    val isFinished: Boolean

}
