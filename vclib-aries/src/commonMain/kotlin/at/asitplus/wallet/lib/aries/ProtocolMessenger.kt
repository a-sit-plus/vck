package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.msg.ProblemReport
import io.github.aakira.napier.Napier

/**
 * Allows for multiplexing of several active runs of a message protocol
 */
abstract class ProtocolMessenger<T : ProtocolStateMachine<U>, U>(
    private val messageWrapper: MessageWrapper,
    private val createProtocolWhenNotActive: Boolean = true,
    private val signInitialMessage: Boolean = true,
    private val signFollowingMessages: Boolean = true,
    private val signAndEncryptFollowingMessages: Boolean = true,
    private val protocolRunManager: ProtocolRunManager<T, U> = ProtocolRunManager(),
) {
    protected abstract fun createProtocolInstance(): T

    suspend fun startCreatingInvitation(): NextMessage {
        val protocol = createProtocolInstance()
            .also { protocolRunManager.addProtocol(it) }
        return start(protocol.startCreatingInvitation())
    }

    suspend fun startDirect(): NextMessage {
        val protocol = createProtocolInstance()
            .also { protocolRunManager.addProtocol(it) }
        return start(protocol.startDirect())
    }

    private suspend fun start(next: InternalNextMessage): NextMessage {
        when (next) {
            is InternalNextMessage.Finished -> {
                return NextMessage.Error("finished not expected")
                    .also { Napier.w("Finished not expected") }
            }

            is InternalNextMessage.IncorrectState -> {
                return NextMessage.Error(next.reason)
                    .also { Napier.w("Incorrect state") }
            }

            is InternalNextMessage.SendAndWrap -> {
                if (signInitialMessage) {
                    val signedMessage = messageWrapper.createSignedJwt(next.message)
                        ?: return NextMessage.SendProblemReport("Can't create signed message", next.endpoint)
                    return NextMessage.Send(signedMessage, next.endpoint)
                }
                return NextMessage.Send(next.message.serialize(), next.endpoint)
            }

            is InternalNextMessage.SendProblemReport -> {
                if (signInitialMessage) {
                    val signedMessage = messageWrapper.createSignedJwt(next.message)
                        ?: return NextMessage.SendProblemReport("Could not sign message", next.endpoint)
                    return NextMessage.SendProblemReport(signedMessage, next.endpoint)
                }
                return NextMessage.SendProblemReport(next.message.serialize(), next.endpoint)
            }
        }
    }

    /**
     * Will be called by Apps to signal aborting a protocol run
     * (Cleanup will happen in [ProtocolRunManager])
     */
    suspend fun abortWithProblemReport(code: String): NextMessage {
        val problemReport = ProblemReporter().problemInternal(null, code)
        return wrapProblemReportMessage(problemReport)
    }

    /**
     * Parses an incoming message and tries to find a protocol instance that can handle it.
     * May create a new protocol instance if [createProtocolWhenNotActive] is set.
     */
    suspend fun parseMessage(it: String): NextMessage {
        val parsedMessage = messageWrapper.parseMessage(it)
        if (parsedMessage !is ReceivedMessage.Success)
            return NextMessage.Error("could not parse received message")
                .also { Napier.w("Could not parse received message") }
        if (parsedMessage.body is ProblemReport)
            return NextMessage.ReceivedProblemReport(parsedMessage.body)
        val result = findActiveProtocolRun(parsedMessage)
        if (result is NextMessage.Error && createProtocolWhenNotActive) {
            createProtocolInstance()
                .also { protocolRunManager.addProtocol(it) }
            return findActiveProtocolRun(parsedMessage)
        }
        return result
    }

    /**
     * Finds a protocol instance in [protocolRunManager] that can actually parse the message,
     * i.e. it is in the correct state, and the threadIds are matching
     */
    private suspend fun findActiveProtocolRun(parsedMessage: ReceivedMessage.Success): NextMessage {
        protocolRunManager.getActiveRuns().forEach { protocol ->
            when (val next = protocol.parseMessage(
                parsedMessage.body,
                parsedMessage.senderKey ?: return NextMessage.Error("No sender key present")
                    .also { Napier.w("No sender key present") })) {
                is InternalNextMessage.Finished -> return NextMessage.Result(protocol.getResult())
                is InternalNextMessage.SendAndWrap -> return wrapNextMessage(next)
                is InternalNextMessage.SendProblemReport -> return wrapProblemReportMessage(next)
                is InternalNextMessage.IncorrectState -> {
                    // continue to search a matching protocol instance
                }
            }
        }
        return NextMessage.Error("no active protocol")
            .also { Napier.w("No active protocol") }
    }

    private suspend fun wrapNextMessage(next: InternalNextMessage.SendAndWrap): NextMessage {
        if (signAndEncryptFollowingMessages && next.senderKey != null) {
            val signedAndEncryptedJwe = messageWrapper.createSignedAndEncryptedJwe(next.message, next.senderKey)
                ?: return NextMessage.SendProblemReport("Could not sign message", next.endpoint)
            return NextMessage.Send(signedAndEncryptedJwe, next.endpoint)
        }
        if (signFollowingMessages) {
            val signedJwt = messageWrapper.createSignedJwt(next.message)
                ?: return NextMessage.SendProblemReport("Could not sign message", next.endpoint)
            return NextMessage.Send(signedJwt, next.endpoint)
        }
        return NextMessage.Send(next.message.serialize(), next.endpoint)
    }

    private suspend fun wrapProblemReportMessage(next: InternalNextMessage.SendProblemReport): NextMessage {
        if (signAndEncryptFollowingMessages && next.senderKey != null) {
            val signedAndEncryptedJwe = messageWrapper.createSignedAndEncryptedJwe(next.message, next.senderKey)
                ?: return NextMessage.SendProblemReport("Could not sign message", next.endpoint)
            return NextMessage.SendProblemReport(signedAndEncryptedJwe, next.endpoint)
        }
        if (signFollowingMessages) {
            val signedJwt = messageWrapper.createSignedJwt(next.message)
                ?: return NextMessage.SendProblemReport(next.message.serialize(), next.endpoint)
            return NextMessage.SendProblemReport(signedJwt, next.endpoint)
        }
        return NextMessage.SendProblemReport(next.message.serialize(), next.endpoint)
    }

}


