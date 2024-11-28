package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc9110.HttpFieldLine
import at.asitplus.wallet.lib.data.rfc9110.HttpFieldValue
import at.asitplus.wallet.lib.data.rfc9110.HttpHeader
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestMessage
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestMessageControlData
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestMethod
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestTarget

data class StatusListRequestMessage(
    val host: UniformResourceIdentifier,
    /**
     * The Relying Party SHOULD send the following Accept-Header to indicate the requested
     * response type:
     *
     * "application/statuslist+jwt" for Status List Token in JWT format
     * "application/statuslist+cwt" for Status List Token in CWT format
     */
    val accept: List<StatusListTokenMediaType>?,
) {
    /**
     * To obtain the Status List Token, the Relying Party MUST send an HTTP GET request to the
     * URI provided in the Referenced Token.
     */
    val method: HttpRequestMethod
        get() = HttpRequestMethod.Get

    fun toHttpRequestMessage() = HttpRequestMessage(
        controlData = HttpRequestMessageControlData(
            requestMethod = method,
            requestTarget = HttpRequestTarget(host.value),
        ),
        headers = accept?.map { acceptedType ->
            HttpFieldLine(
                fieldName = HttpHeader.Accept,
                fieldValue = HttpFieldValue(acceptedType.value),
            )
        } ?: listOf()
    )
}

