package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.jsonForParameters
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject

class RequestParser(
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a
     * [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
     * or the request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    @Deprecated("No longer used, decision moved to `AuthorizationRequestValidator`")
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _: Any -> true },
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
                // RFC 9101, 6.2: the request object must not contain `request` or `request_uri` itself
                .also { resolved ->
                    if (resolved.parameters is JarRequestParameters)
                        throw InvalidRequest("request object must not contain `request` or `request_uri`")
                }
        } ?: this

    private fun String.parseFromParameters(): RequestParametersFrom<*>? = catchingUnwrapped {
        Url(this).let {
            RequestParametersFrom.Uri(
                url = it,
                parameters = jsonForParameters.decodeFromJsonElement(
                    RequestParameters.serializer(),
                    it.parameters.flattenEntries().toMap().decodeFromUrlQuery<JsonObject>()
                )
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
    ): RequestParametersFrom<*>? = parameters.request?.let {
        // no JSON fallback: RFC 9101, 4 admits only a signed, or a signed and encrypted, request object. Throwing
        // rather than returning null keeps this arm parallel to the `request_uri` one below, and reports the actual
        // problem instead of letting the elvis fall through to a request that is missing every parameter
        it.parseAsJwsRequest(parent)
            ?: throw InvalidRequest("request content not a valid request object")
    } ?: parameters.requestUri?.let { uri ->
        val method = parameters.requestUriMethod?.toHttpMethod() ?: HttpMethod.Get
        // only the POST request to the request URI endpoint has a channel for these, see OpenID4VP 1.0, 5.10, and it
        // is built once per request, since it carries the key the verifier shall encrypt this very request to
        val requestObjectParameters = if (method == HttpMethod.Post) buildRequestObjectParameters() else null
        val content = remoteResourceRetriever(parameters.resourceRetrieverInput(uri, method, requestObjectParameters))
            ?: throw InvalidRequest("could not retrieve request object from request_uri: $uri")
        val expectedKeyId = requestObjectParameters.expectedEncryptionKeyId()
        val fromJwe = content.parseAsJweRequest(parent, expectedKeyId)
        // a non-null `expectedKeyId` means we advertised a key in `wallet_metadata`, i.e. this was the POST fetch,
        // the only flow in which the verifier had the chance to encrypt at all
        if (fromJwe == null && requireEncryptedRequests && expectedKeyId != null)
            throw InvalidRequest("request object from $uri is not encrypted, but we require encryption")
        (fromJwe
            ?: content.parseAsJwsRequest(parent)
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

    private fun JarRequestParameters.resourceRetrieverInput(
        uri: String,
        method: HttpMethod,
        requestObjectParameters: RequestObjectParameters?,
    ): RemoteResourceRetrieverInput = RemoteResourceRetrieverInput(
        url = uri,
        method = method,
        headers = mapOf(HttpHeaders.Accept to MediaTypes.Application.AUTHZ_REQ_JWT),
        requestObjectParameters = requestObjectParameters
    )

    private suspend fun String.parseAsJwsRequest(
        parent: RequestParametersFrom<out RequestParameters>?,
        decryptedFrom: JweHeader? = null,
    ): RequestParametersFrom<*>? =
        catching { JwsCompactTyped<RequestParameters>(this) }
            .getOrNull()?.let { jws ->
                jws.jws.requireRequestObjectType()
                RequestParametersFrom.Jws(
                    jws = jws.jws,
                    parameters = jws.payload,
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
        return decrypted.payload.parseAsJwsRequest(parent, jwe.header)
            ?: throw InvalidRequest("Decrypted request object is not a signed request object")
    }

}
