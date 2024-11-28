package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListRequestMessage
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc9110.HttpHeader
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestMessage
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestMessageControlData
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestResolver
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestTarget
import at.asitplus.wallet.lib.data.rfc9110.HttpResponseMessage

interface StatusListTokenResolver<StatusListToken : Any> {
    /**
     *  8.1. Status List Request
     *
     * To obtain the Status List Token, the Relying Party MUST send an HTTP GET request to the URI
     * provided in the Referenced Token.
     * The HTTP endpoint SHOULD support the use of Cross-Origin Resource Sharing (CORS) [CORS]
     * and/or other methods as appropriate to enable Browser-Based clients to access it.The Relying
     * Party SHOULD send the following Accept-Header to indicate the requested response type:
     *  "application/statuslist+jwt" for Status List Token in JWT format
     *  "application/statuslist+cwt" for Status List Token in CWT format
     *
     * If the Relying Party does not send an Accept Header, the response type is assumed to be
     * known implicit or out-of-band.
     *
     * A successful response that contains a Status List Token MUST
     * use an HTTP status code in the 2xx range.A response MAY also choose to redirect the client
     * to another URI using a HTTP status code in the 3xx range, which clients SHOULD follow. A
     * client SHOULD detect and intervene in cyclical redirections (i.e., "infinite" redirection
     * loops).
     *
     * The following are non-normative examples for a request and response for a Status List
     * Token with type application/statuslist+jwt:
     *
     * GET /statuslists/1 HTTP/1.1
     * Host: example.com
     * Accept: application/statuslist+jwt
     *
     * HTTP/1.1 200 OK
     * Content-Type: application/statuslist+jwt
     *
     * eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.e
     * yJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9le
     * GFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQ
     * WhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsI
     * nR0bCI6NDMyMDB9.cyiLrzQVZvPnAXO07s7EzUqBB-62Sa39XfZMopIfEVQ819dBFvgv
     * wvQmJd8OHDj6l6Ct-tG3CLUG8LaxubYL6g
     *
     *  8.2. Status List Response
     *
     * In the successful response, the Status Provider MUST use the following content-type:
     *
     * "application/statuslist+jwt" for Status List Token in JWT format
     *
     * "application/statuslist+cwt" for Status List Token in CWT format
     * In the case of "application/statuslist+jwt", the response MUST be of type JWT and follow the
     * rules of Section 5.1. In the case of "application/statuslist+cwt", the response MUST be of
     * type CWT and follow the rules of Section 5.2.
     */
    suspend operator fun invoke(uri: UniformResourceIdentifier): StatusListToken

    class FromStatusListRequestResolver<StatusListToken : Any>(
        val acceptedTypes: List<StatusListTokenMediaType>?,
        val resolveStatusListRequest: suspend (StatusListRequestMessage) -> StatusListToken
    ) : StatusListTokenResolver<StatusListToken> {
        override suspend fun invoke(uri: UniformResourceIdentifier): StatusListToken {
            return resolveStatusListRequest(buildStatusListRequest(uri))
        }

        fun buildStatusListRequest(uri: UniformResourceIdentifier) = StatusListRequestMessage(
            accept = acceptedTypes,
            host = uri,
        )
    }

    class FromHttpRequestResolver<StatusListToken : Any>(
        val acceptedTypes: List<StatusListTokenMediaType>?,
        val httpRequestResolver: HttpRequestResolver,
        val httpResponseContentToStatusListToken: (StatusListTokenMediaType, ByteArray) -> StatusListToken,
    ) : StatusListTokenResolver<StatusListToken> {
        override suspend fun invoke(uri: UniformResourceIdentifier): StatusListToken {
            val requestMessage = StatusListRequestMessage(
                accept = acceptedTypes,
                host = uri,
            ).toHttpRequestMessage()

            val response = followRedirects(requestMessage)

            if(response.controlData?.statusCode?.isSuccessful != true) {
                throw IllegalStateException("Response did not provide a successful status code.")
            }

            val contentType = response.headers?.firstOrNull {
                it.fieldName == HttpHeader.ContentType
            } ?: throw IllegalStateException("Response did not provide a content type.")
            val content = response.content
                ?: throw IllegalStateException("Response did not provide any content.")

            val statusListTokenMediaType = StatusListTokenMediaType.valueOf(
                MediaType(contentType.fieldValue.value)
            )

            return httpResponseContentToStatusListToken(statusListTokenMediaType, content)
        }

        private suspend fun followRedirects(requestMessage: HttpRequestMessage): HttpResponseMessage {
            var nextUri = requestMessage.controlData?.requestTarget
                ?: throw IllegalArgumentException("Message did not specify a request target.")

            val visitedLocations = mutableListOf<HttpRequestTarget>()
            while (nextUri !in visitedLocations) {
                visitedLocations.add(nextUri)

                val response = httpRequestResolver.resolve(
                    requestMessage.copy(
                        controlData = HttpRequestMessageControlData(
                            requestMethod = requestMessage.controlData.requestMethod,
                            requestTarget = nextUri,
                        ),
                    )
                )

                val statusCode = response.controlData?.statusCode
                    ?: throw IllegalStateException("Response did not specify a status code.")
                when {
                    statusCode.isSuccessful -> return response
                    statusCode.isRedirection -> {
                        val redirectLocation = response.headers?.firstOrNull {
                            it.fieldName == HttpHeader.Location
                        }?.fieldValue?.value
                            ?: throw IllegalStateException("Response status code specified a redirect, but no redirect location header was found.")

                        nextUri = HttpRequestTarget(redirectLocation)
                    }

                    else -> throw IllegalStateException("Response from the status list request was neither successful nor a redirect.")
                }
            }
            throw IllegalStateException("Aborting request resolving: Cyclic redirection was detected.")
        }
    }
}