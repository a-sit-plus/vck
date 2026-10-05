package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.openid.toFormParameters
import io.ktor.http.*

class RequestParser(
    /**
     * Fetches a request object passed by reference in `request_uri`, see [extractRequest].
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     * Wallets fetch request objects with [OpenId4VpProtocolClient] instead.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /** Holds the ephemeral encryption keys advertised in `wallet_metadata` when fetching a request object with POST. */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
    /** Decrypts request objects sent by the verifier, keyed by the `kid` of the JWE. */
    private val decryptRequestObject: DecryptJweFun? =
        ephemeralEncryptionKeyService?.let { DecryptJweWithEphemeralKey(it) },
    /**
     * Set to reject a plain request object served at a `request_uri` we have fetched with POST, i.e. the one flow in
     * which we advertised an encryption key, see [OpenId4VpHolder]. Requests that never gave the verifier a key to
     * encrypt to at all, i.e. `request` by value, `request_uri_method=get`, and plain requests carrying their
     * parameters in the URL, are still accepted: callers wanting those rejected too can do so themselves, by looking
     * at [RequestParametersFrom.decryptedFrom].
     */
    private val requireEncryptedRequests: Boolean = false,
    /**
     * Callback to load [RequestObjectParameters] when loading a request object by reference (e.g. from `request_uri`)
     */
    private val buildRequestObjectParameters: suspend () -> RequestObjectParameters? = { null },
) {
    /** Result of [parseWithoutFetching]. */
    internal sealed interface ParsedRequest {
        /** The request, including its request object, if that was passed by value in `request`. */
        data class Resolved(val request: RequestParametersFrom<*>) : ParsedRequest

        /**
         * The request object is passed by reference: fetch it from [uri] with [method], sending
         * [requestObjectParameters] as form for POST, and pass its content to [resolveFetchedRequestObject].
         *
         * [requestObjectParameters] are built once, as they carry the wallet nonce and the encryption key for exactly
         * this request.
         */
        class ByReference(
            val uri: String,
            val method: HttpMethod,
            val requestObjectParameters: RequestObjectParameters?,
            val parent: RequestParametersFrom<out RequestParameters>?,
        ) : ParsedRequest
    }

    /**
     * Pass in the request by a relying party, that is either a complete URL,
     * or the POST body (e.g. the form-serialized values of the authorization request),
     * or a serialized JWS (which may have been extracted from a `request` parameter),
     * to parse the [AuthenticationRequestParameters], wrapped in [RequestParametersFrom].
     */
    suspend fun parseRequestParameters(
        input: String,
    ): KmmResult<RequestParametersFrom<*>> = catching {
        input.parseParameters().extractRequest()
    }

    /**
     * Parses [input] like [parseRequestParameters], but returns where to fetch a request object passed by reference
     * instead of fetching it with [remoteResourceRetriever].
     */
    internal suspend fun parseWithoutFetching(
        input: String,
    ): ParsedRequest {
        val parsed = input.parseParameters()
        val jar = parsed.parameters as? JarRequestParameters
            ?: return ParsedRequest.Resolved(parsed)
        jar.request?.let {
            return ParsedRequest.Resolved(it.parseRequestObjectByValue(parsed).requireNotNested())
        }
        val uri = jar.requestUri
            ?: throw InvalidRequest("request contains neither `request` nor `request_uri`")
        return jar.toReference(uri, parsed)
    }

    /**
     * Resolves the request object fetched for [reference] from its [content], i.e. decrypts and parses it, as
     * [parseRequestParameters] does after fetching it.
     */
    internal suspend fun resolveFetchedRequestObject(
        reference: ParsedRequest.ByReference,
        content: String,
    ): RequestParametersFrom<*> = reference.resolve(content).requireNotNested()

    private suspend fun String.parseParameters(): RequestParametersFrom<out RequestParameters> =
        parseAsJwsRequest(null)
            ?: parseFromParameters()
            ?: parseFromJson(null)
            ?: throw InvalidRequest("parse error: $this")

    /**
     * Resolves a JAR request, i.e. the request object referenced in `request_uri` or carried in `request`, into the
     * request parameters it holds. A JAR request we can not resolve is an error: passing it on unresolved would look
     * like a successfully parsed request, but carry none of the parameters it is supposed to transport.
     */
    private suspend fun RequestParametersFrom<out RequestParameters>.extractRequest(): RequestParametersFrom<*> =
        (this.parameters as? JarRequestParameters)?.let { jar ->
            (extractRequest(jar, this)
                ?: throw InvalidRequest("request contains neither `request` nor `request_uri`"))
                .requireNotNested()
        } ?: this

    /** RFC 9101, 6.2: the request object must not contain `request` or `request_uri` itself. */
    private fun RequestParametersFrom<*>.requireNotNested(): RequestParametersFrom<*> = also {
        if (parameters is JarRequestParameters)
            throw InvalidRequest("request object must not contain `request` or `request_uri`")
    }

    private fun String.parseFromParameters(): RequestParametersFrom<*>? = catchingUnwrapped {
        Url(this).let {
            RequestParametersFrom.Uri(
                url = it,
                parameters = RequestParametersSerializer.decodeFormParameters(it.encodedQuery.toFormParameters())
            )
        }
    }.getOrNull()

    private fun String.parseFromJson(
        parent: RequestParametersFrom<out RequestParameters>?,
        decryptedFrom: JweHeader? = null,
    ): RequestParametersFrom<*>? = catchingUnwrapped {
        val params = joseCompliantSerializer.decodeFromString(RequestParameters.serializer(), this)
        RequestParametersFrom.Json(this, params, (parent as? RequestParametersFrom.Uri)?.url, decryptedFrom)
    }.getOrNull()

    /**
     * Resolves the request object of the JAR request in [parameters], either from `request`, or by fetching the
     * `request_uri` with [remoteResourceRetriever].
     *
     * Returns `null` only if the request carries neither of the two, and throws if the request object can not be
     * retrieved, or is not a valid request object.
     */
    suspend fun extractRequest(
        parameters: JarRequestParameters,
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*>? = parameters.request?.parseRequestObjectByValue(parent)
        ?: parameters.requestUri?.let { uri ->
            val reference = parameters.toReference(uri, parent)
            val content = remoteResourceRetriever(reference.toResourceRetrieverInput())
                ?: throw InvalidRequest("could not retrieve request object from request_uri: $uri")
            reference.resolve(content)
        }

    /**
     * No JSON fallback: RFC 9101, 4 admits only a signed, or a signed and encrypted, request object. Throwing rather
     * than returning null keeps this parallel to [resolve] for `request_uri`, and reports the actual problem instead
     * of letting the elvis fall through to a request that is missing every parameter.
     */
    private suspend fun String.parseRequestObjectByValue(
        parent: RequestParametersFrom<out RequestParameters>?,
    ): RequestParametersFrom<*> = parseAsJwsRequest(parent)
        ?: throw InvalidRequest("request content not a valid request object")

    private suspend fun JarRequestParameters.toReference(
        uri: String,
        parent: RequestParametersFrom<out RequestParameters>?,
    ): ParsedRequest.ByReference {
        val method = requestUriMethod?.toHttpMethod() ?: HttpMethod.Get
        // only the POST request to the request URI endpoint has a channel for these, see OpenID4VP 1.0, 5.10, and it
        // is built once per request, since it carries the key the verifier shall encrypt this very request to
        val requestObjectParameters = if (method == HttpMethod.Post) buildRequestObjectParameters() else null
        return ParsedRequest.ByReference(uri, method, requestObjectParameters, parent)
    }

    private suspend fun ParsedRequest.ByReference.resolve(content: String): RequestParametersFrom<*> {
        val expectedKeyId = requestObjectParameters.expectedEncryptionKeyId()
        val fromJwe = content.parseAsJweRequest(parent, expectedKeyId)
        // a non-null `expectedKeyId` means we advertised a key in `wallet_metadata`, i.e. this was the POST fetch,
        // the only flow in which the verifier had the chance to encrypt at all
        if (fromJwe == null && requireEncryptedRequests && expectedKeyId != null)
            throw InvalidRequest("request object from $uri is not encrypted, but we require encryption")
        return (fromJwe
            ?: content.parseAsJwsRequest(
                parent,
                invalidRequestDescription = "request_uri content not a valid request object: $uri",
            )
            ?: throw InvalidRequest("request_uri content not a valid request object: $uri"))
            .also { request -> request.requireWalletNonce(requestObjectParameters?.walletNonce) }
    }

    /** The `kid` of the encryption key we have advertised in `wallet_metadata` for this very request. */
    private fun RequestObjectParameters?.expectedEncryptionKeyId(): String? =
        this?.walletMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()?.keyId

    /**
     * Per OpenID4VP 1.0, 5.10.1:
     * If we passed a `wallet_nonce` when fetching the request object, it MUST come back in the request object,
     * otherwise we MUST terminate request processing.
     */
    private fun RequestParametersFrom<*>.requireWalletNonce(sent: String?) {
        if (sent == null) return
        val received = (parameters as? AuthenticationRequestParameters)?.walletNonce
        if (received != sent)
            throw InvalidRequest("wallet_nonce we sent is missing from the request object, got: $received")
    }

    private fun ParsedRequest.ByReference.toResourceRetrieverInput() = RemoteResourceRetrieverInput(
        url = uri,
        method = method,
        headers = mapOf(HttpHeaders.Accept to MediaTypes.Application.AUTHZ_REQ_JWT),
        requestObjectParameters = requestObjectParameters
    )

    private suspend fun String.parseAsJwsRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
        decryptedFrom: JweHeader? = null,
        invalidRequestDescription: String = "request content not a valid request object",
    ): RequestParametersFrom<*>? {
        val jws = catching { JwsCompact(this) }.getOrNull() ?: return null
        val typedJws = catching { jws.typed<RequestParameters, JwsCompact>() }.getOrElse {
            throw InvalidRequest(invalidRequestDescription, it)
        }
        typedJws.jws.requireRequestObjectType()
        return RequestParametersFrom.Jws(
            jws = typedJws.jws,
            parameters = typedJws.payload,
            parent = (parent as? RequestParametersFrom.Uri)?.url,
            decryptedFrom = decryptedFrom,
        )
    }

    /**
     * Decrypts a request object encrypted to the key we have advertised in `wallet_metadata`, as per
     * OpenID4VP 1.0, 5.10 and parses the plaintext, which is a signed or plain request object.
     *
     * Returns `null` if this is not a JWE at all, and throws if it is one that we can't or shouldn't decrypt.
     */
    private suspend fun String.parseAsJweRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
        expectedKeyId: String?,
    ): RequestParametersFrom<*>? {
        if (count { it == '.' } != 4) return null
        val jwe = JweEncrypted.deserialize(this).getOrNull() ?: return null
        if (expectedKeyId == null)
            throw InvalidRequest("Verifier sent an encrypted request, but we did not request encryption")
        if (jwe.header.keyId != expectedKeyId)
            throw InvalidRequest("Encrypted request key does not match the key we advertised")
        if (decryptRequestObject == null)
            throw InvalidRequest("Verifier sent an encrypted request, we can't decrypt it")
        val decrypted = decryptRequestObject(jwe).getOrElse {
            throw InvalidRequest("Decryption of request object failed", it)
        }
        // OpenID4VP 1.0, 5.10.1 permits encryption only in addition to signing, never instead of it, and per
        // RFC 9101, 6.1 decrypting a request object yields "a signed Request Object"
        return decrypted.payload.parseAsJwsRequest(
            parent = parent,
            decryptedFrom = jwe.header,
            invalidRequestDescription = "Decrypted request object is not a signed request object",
        )
            ?: throw InvalidRequest("Decrypted request object is not a signed request object")
    }

}
