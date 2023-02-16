package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.msg.ProblemReport


sealed class NextMessage {

    /**
     * Protocol has finished, we got the [result]
     */
    data class Result<U>(val result: U) : NextMessage()

    /**
     * Please send [message] to [endpoint] to continue the protocol
     */
    data class Send(val message: String, val endpoint: String?) : NextMessage()

    /**
     * Please send [message] to [endpoint], contains a problem report
     */
    data class SendProblemReport(val message: String, val endpoint: String?) : NextMessage()

    /**
     * Can't continue with protocol
     */
    data class Error(val reason: String) : NextMessage()

    /**
     * Received a Problem Report from other party
     */
    data class ReceivedProblemReport(val message: ProblemReport) : NextMessage()
}

