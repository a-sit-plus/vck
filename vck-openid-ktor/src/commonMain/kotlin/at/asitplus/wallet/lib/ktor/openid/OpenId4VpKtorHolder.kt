package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.encodeToParameters
import at.asitplus.openid.formUrlEncode
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.supreme.UserInitiatedCancellationReason
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.openid.DcApiHolder
import at.asitplus.wallet.lib.openid.DcApiPreparationState
import at.asitplus.wallet.lib.openid.Iso180137AnnexCHolder
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import at.asitplus.wallet.lib.openid.OpenId4VpProtocolClient
import at.asitplus.wallet.lib.openid.RelyingPartyTrust
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.utils.io.core.*

@Deprecated("Renamed", ReplaceWith("OpenId4VpKtorHolder"))
typealias OpenId4VpWallet = OpenId4VpKtorHolder

/**
 * Implements the wallet side of
 * [Self-Issued OpenID Provider v2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
 * and
 * [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
 * with ktor, by sending the requests of [OpenId4VpProtocolClient], which implements the protocol.
 *
 * The parameters after [httpClient] are passed on to [OpenId4VpHolder], see there.
 */
class OpenId4VpKtorHolder(
    /**
     * The app's ktor client, i.e. with its engine and logging. This class sends its requests with a copy that does not
     * follow redirects (see [HttpClient.config]), setting content type and status handling per request. Plugins must
     * not re-send requests or react to error statuses: a re-sent authorization response submits the presentation
     * twice.
     */
    httpClient: HttpClient,
    /** Key material used to encrypt responses and sign ID tokens. */
    keyMaterial: KeyMaterial,
    /** Holds the credentials and creates the verifiable presentation. */
    holder: Holder,
    /** Encrypts the authn response to the verifier, if this has been requested. */
    encryptJarm: EncryptJweFun = EncryptJwe(),
    /** Advertised in [OpenId4VpHolder.metadata] and compared against holder's requirements. */
    supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Advertised as `issuer` in [OpenId4VpHolder.metadata]. */
    clientId: String = "https://wallet.a-sit.at/",
    /** Advertised as `authorization_endpoint` in [OpenId4VpHolder.metadata]. */
    authorizationEndpoint: String = "openid4vp:",
    /** How to establish trust in the relying party sending an authorization request, or `null` for trusting all. */
    relyingPartyTrust: Set<RelyingPartyTrust>? = null,
    /** Stores our nonce used when fetching authn requests using POST. */
    walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    /** Source for random bytes, i.e., nonces for encrypted responses. */
    randomSource: RandomSource = RandomSource.Secure,
    /** Callback to load encryption keys for pre-registered clients. */
    lookupJsonWebKeysForClient: (OpenId4VpHolder.JsonWebKeyLookupInput) -> JsonWebKeySet? = { null },
    /** Supplies the allowed schemes for origins received with OpenID4VP DC API requests. */
    allowedDcApiOriginSchemes: suspend () -> Set<String> = { OpenId4VpHolder.DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES },
    /** Set to accept encrypted authorization requests fetched with a POST (when RP supports that). */
    ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
    /** Advertised in `wallet_metadata` to encrypt authorization requests, see [ephemeralEncryptionKeyService]. */
    supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
    /** Set to reject a plain request object we have fetched with POST (when RP supports that) */
    requireEncryptedRequests: Boolean = false,
) {

    /**
     * @param engine ktor engine to make requests to the Relying Party.
     * @param httpClientConfig Additional configuration for building the HTTP client, e.g. callers may enable logging.
     * @param keyMaterial Key Material to be passed on to [OpenId4VpHolder]
     * @param holderAgent Holder Agent to be passed on to [OpenId4VpHolder]
     * @param randomSource Source for random bytes, i.e., nonces for encrypted responses.
     * @param allowedDcApiOriginSchemes Supplies the allowed origin schemes for OpenID4VP DC API requests.
     * @param relyingPartyTrust How to establish trust in the relying party, to be passed on to [OpenId4VpHolder].
     * @param ephemeralEncryptionKeyService Set to accept encrypted authorization requests, to be passed on to
     * [OpenId4VpHolder].
     * @param requireEncryptedRequests Set to reject plain request objects fetched with POST, to be passed on to
     * [OpenId4VpHolder].
     */
    @Deprecated(
        "Pass the app's HttpClient instead of engine and httpClientConfig, and the holder as holder; " +
                "this also takes every other parameter of OpenId4VpHolder"
    )
    constructor(
        engine: HttpClientEngine,
        httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
        keyMaterial: KeyMaterial,
        holderAgent: HolderAgent,
        randomSource: RandomSource = RandomSource.Secure,
        allowedDcApiOriginSchemes: suspend () -> Set<String> = {
            OpenId4VpHolder.DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES
        },
        relyingPartyTrust: Set<RelyingPartyTrust>? = null,
        ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
        requireEncryptedRequests: Boolean = false,
    ) : this(
        httpClient = buildHttpClient(engine, httpClientConfig = httpClientConfig),
        keyMaterial = keyMaterial,
        holder = holderAgent,
        relyingPartyTrust = relyingPartyTrust,
        randomSource = randomSource,
        allowedDcApiOriginSchemes = allowedDcApiOriginSchemes,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        requireEncryptedRequests = requireEncryptedRequests,
    )

    sealed interface AuthenticationResult

    data class AuthenticationSuccess(
        val redirectUri: String? = null,
    ) : AuthenticationResult

    data class AuthenticationForward(
        val authenticationResponseResult: AuthenticationResponseResult.DcApi,
    ) : AuthenticationResult


    /** Sends the requests, configured not to follow redirects. */
    private val client = httpClient.config { followRedirects = false }

    val openId4VpHolder = OpenId4VpHolder(
        keyMaterial = keyMaterial,
        holder = holder,
        encryptJarm = encryptJarm,
        supportedAlgorithms = supportedAlgorithms,
        clientId = clientId,
        authorizationEndpoint = authorizationEndpoint,
        // only used by the deprecated methods of OpenId4VpHolder, this class sends the exchanges of protocolClient
        remoteResourceRetriever = { client.fetch(it) },
        relyingPartyTrust = relyingPartyTrust,
        walletNonceMapStore = walletNonceMapStore,
        randomSource = randomSource,
        lookupJsonWebKeysForClient = lookupJsonWebKeysForClient,
        allowedDcApiOriginSchemes = allowedDcApiOriginSchemes,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        supportedJweEncryptionAlgorithms = supportedJweEncryptionAlgorithms,
        requireEncryptedRequests = requireEncryptedRequests,
    )

    val iso180137AnnexCHolder = Iso180137AnnexCHolder(
        keyMaterial = keyMaterial,
        holder = holder,
    )

    val dcApiHolder = DcApiHolder(
        keyMaterial = keyMaterial,
        holder = holder,
        openId4VpHolder = openId4VpHolder,
        iso180137AnnexCHolder = iso180137AnnexCHolder,
    )

    internal val protocolClient = OpenId4VpProtocolClient(openId4VpHolder)

    /**
     * Sends an error response with the appropriate method.
     * Returns nothing as we don't expect a useful response from the remote verifier.
     */
    suspend fun sendAuthnErrorResponse(
        error: Throwable,
        state: AuthorizationResponsePreparationState,
    ) {
        catchingUnwrapped {
            Napier.i("sendAuthnErrorResponse $error, ${state.request}")
            openId4VpHolder.createAuthnErrorResponse(error, state).getOrThrow().let {
                when (it) {
                    is AuthenticationResponseResult.Post -> postResponse(it)
                    is AuthenticationResponseResult.Redirect -> redirectResponse(it)
                    else -> Napier.w("Unsupported error response mode: $it")
                }
            }
        }
    }

    suspend fun startAuthorizationResponsePreparation(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthorizationResponsePreparationState> =
        openId4VpHolder.startAuthorizationResponsePreparation(request)

    /**
     * Parses [input], loads the request object, and validates the request, see
     * [OpenId4VpProtocolClient.prepareAuthorizationResponse].
     */
    suspend fun startAuthorizationResponsePreparation(
        input: String,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        client.execute(protocolClient.prepareAuthorizationResponse(input))
    }

    /** Prepares either an OpenID4VP or Annex C request received through the Digital Credentials API. */
    suspend fun prepareDcApiRequest(
        request: RequestParametersFrom.DcApiRequest,
    ): KmmResult<DcApiPreparationState> =
        dcApiHolder.startAuthorizationResponsePreparation(request)

    /**
     * Calls [openId4VpHolder] to finalize the authentication response.
     * In case the result shall be POSTed to the verifier, we call [client] to do that,
     * and return the `redirect_uri` of that POST (which the Wallet may open in a browser),
     * see [OpenId4VpProtocolClient.sendAuthorizationResponse].
     * In case the result shall be sent as a redirect to the verifier, we return that URL.
     */
    suspend fun startPresentationReturningUrl(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationSuccess> = catching {
        Napier.i("startPresentation: $request")
        openId4VpHolder.createAuthnResponse(request).getOrThrow().let {
            when (it) {
                is AuthenticationResponseResult.Post -> postResponse(it)
                is AuthenticationResponseResult.Redirect -> redirectResponse(it)
                is AuthenticationResponseResult.DcApi -> throw UnsupportedOperationException("Returning a URL not supported for DC API")
            }
        }
    }

    /**
     * Calls [openId4VpHolder] to finalize the authentication response.
     * In case the result shall be POSTed to the verifier, we call [client] to do that,
     * and return the `redirect_uri` of that POST (which the Wallet may open in a browser),
     * see [OpenId4VpProtocolClient.sendAuthorizationResponse].
     * In case the result shall be sent as a redirect to the verifier, we return that URL.
     * In case the result shall be returned via the Digital Credentials API, an [AuthenticationForward]
     * will be returned with the result to be forwarded.
     *
     * Exceptions may be sent to the verifier in [sendAuthnErrorResponse].
     */
    suspend fun finalizeAuthorizationResponse(
        preparationState: AuthorizationResponsePreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<AuthenticationResult> = catching {
        Napier.i("startPresentation: $preparationState")
        openId4VpHolder.finalizeAuthorizationResponse(
            preparationState = preparationState,
            credentialPresentation = credentialPresentation
        ).getOrElse {
            if (it !is UserInitiatedCancellationReason) {
                sendAuthnErrorResponse(it, preparationState)
            }
            throw it
        }.let {
            handleResponseResult(it)
        }
    }

    private suspend fun handleResponseResult(
        response: AuthenticationResponseResult,
    ): AuthenticationResult = when (response) {
        is AuthenticationResponseResult.Post -> postResponse(response)
        is AuthenticationResponseResult.Redirect -> redirectResponse(response)
        is AuthenticationResponseResult.DcApi -> AuthenticationForward(response)
    }

    private suspend fun postResponse(it: AuthenticationResponseResult.Post) = run {
        Napier.i("postResponse: $it")
        AuthenticationSuccess(client.execute(protocolClient.sendAuthorizationResponse(it)))
    }

    /**
     * Exceptions may be sent to the verifier in [sendAuthnErrorResponse].
     */
    suspend fun getMatchingCredentials(
        preparationState: AuthorizationResponsePreparationState,
    ) = catching {
        openId4VpHolder.getMatchingCredentials(preparationState).getOrThrow()
    }

    /** Matches credentials through the protocol handler captured by [state]. */
    suspend fun getMatchingCredentials(
        state: DcApiPreparationState,
    ) = catching {
        dcApiHolder.getMatchingCredentials(state).getOrThrow()
    }

    /** Finalizes [state] into a platform-independent Digital Credentials API response model. */
    suspend fun finalizeDcApiResponse(
        state: DcApiPreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ) = catching {
        dcApiHolder.finalizeAuthorizationResponse(
            state = state,
            credentialPresentation = credentialPresentation,
        ).getOrThrow()
    }

    /**
     * Our implementation of ktor's [FormDataContent], but with [contentType] without charset appended,
     * so that some strict mDoc verifiers accept our authn response
     */
    @Deprecated(
        "No longer used: authorization responses are sent by OpenId4VpProtocolClient.sendAuthorizationResponse, " +
                "also without charset in the content type",
    )
    class FormDataContentPlain(
        formData: Parameters,
    ) : OutgoingContent.ByteArrayContent() {
        private val content = formData.formUrlEncode().toByteArray()
        override val contentLength: Long = content.size.toLong()
        override val contentType: ContentType = ContentType.Application.FormUrlEncoded
        override fun bytes(): ByteArray = content
    }


    /**
     * Fetches a request object for the deprecated methods of [openId4VpHolder], i.e. sends the request as
     * [OpenId4VpProtocolClient.prepareAuthorizationResponse] does, and fails for a non-success response.
     */
    @Suppress("DEPRECATION") // throws the subclass of this module, as execute does
    private suspend fun HttpClient.fetch(input: RemoteResourceRetrieverInput): String {
        val isPost = input.method == HttpMethod.Post
        val response = send(
            PreparedHttpRequest(
                url = input.url,
                method = input.method,
                headers = Headers.build {
                    input.headers.forEach { (name, value) -> append(name, value) }
                    if (isPost) append(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
                },
                body = if (isPost) input.requestObjectParameters?.encodeToParameters()?.formUrlEncode().orEmpty()
                else null,
            )
        )
        val body = response.bodyAsText()
        if (!response.status.isSuccess()) throw HttpErrorResponseException(response, body)
        return body
    }

    private fun redirectResponse(it: AuthenticationResponseResult.Redirect) = run {
        Napier.i("redirectResponse: ${it.url}")
        AuthenticationSuccess(it.url)
    }
}

@Deprecated(
    "Moved to vck-openid, which does not depend on a ktor client",
    ReplaceWith("OpenId4VpSuccess", "at.asitplus.wallet.lib.openid.OpenId4VpSuccess"),
)
typealias OpenId4VpSuccess = at.asitplus.wallet.lib.openid.OpenId4VpSuccess
