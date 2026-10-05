package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.TokenInfo
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cookies.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.serialization.json.JsonObject

/**
 * Uses an external OAuth 2.0 Authorization Server with a [at.asitplus.wallet.lib.oidvci.OpenId4VciServer],
 * i.e., delegate authorization to the external AS, and load user info from there
 * (after performing token exchange with the Wallet's access token to get a fresh one).
 * Authenticates with the `clientAttestation` the remote authorization server expects, if any.
 */
class RemoteOAuth2AuthorizationServerAdapter private constructor(
    /** Base URL of the remote Authorization Server. */
    override val publicContext: String,
    /** OAuth 2.0 client to use when exchanging Wallet's token for a fresh access token. */
    private val oauth2Client: OAuth2KtorClient,
    /** Validates access tokens received in [validateAccessToken]. */
    val internalTokenVerificationService: TokenVerificationService,
    /** Used to provide DPoP nonces for credential requests, which will be verified by [internalTokenVerificationService]. */
    val dpopNonceService: NonceService,
    /** [CoroutineScope] to fetch the authorization server's metadata. */
    private val scope: CoroutineScope,
) : OAuth2AuthorizationServerAdapter {

    /**
     * @param publicContext base URL of the remote Authorization Server
     * @param httpClient the app's ktor client, i.e. with its engine and logging. The requests are sent with a copy that
     * does not follow redirects, see [OAuth2KtorClient] for the plugins it must not have.
     * @param internalTokenVerificationService validates access tokens received in [validateAccessToken]
     * @param oauth2Client implements OAuth 2.0 when exchanging Wallet's token for a fresh access token
     * @param clientAttestation authenticates with
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     * at the remote Authorization Server, or `null` to not use it
     * @param verifyTokenIntrospectionJwt verifies the signature of JWT responses of token introspection (RFC 9701)
     * against the keys of the remote Authorization Server; when set, token introspection requests and accepts only JWT
     * responses, when `null` (the default) plain JSON responses
     * @param dpopNonceService used to provide DPoP nonces for credential requests, which will be verified by
     * [internalTokenVerificationService]
     * @param scope [CoroutineScope] to fetch the authorization server's metadata
     */
    constructor(
        publicContext: String,
        httpClient: HttpClient,
        internalTokenVerificationService: TokenVerificationService,
        oauth2Client: OAuth2Client = OAuth2Client(),
        clientAttestation: ClientAttestation? = null,
        verifyTokenIntrospectionJwt: VerifyJwsObjectFun? = null,
        dpopNonceService: NonceService = DefaultNonceService(),
        scope: CoroutineScope = CoroutineScope(Dispatchers.IO),
    ) : this(
        publicContext = publicContext,
        oauth2Client = OAuth2KtorClient(
            httpClient = httpClient,
            oAuth2Client = oauth2Client,
            clientAttestation = clientAttestation,
            verifyTokenIntrospectionJwt = verifyTokenIntrospectionJwt,
        ),
        internalTokenVerificationService = internalTokenVerificationService,
        dpopNonceService = dpopNonceService,
        scope = scope,
    )

    /**
     * @param publicContext Base URL of the remote Authorization Server.
     * @param engine ktor engine to make requests to the verifier.
     * @param cookiesStorage Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     * @param httpClientConfig Additional configuration for building the HTTP client, e.g., callers may enable logging.
     * @param scope [CoroutineScope] to fetch the authorization server's metadata.
     * @param oauth2Client OAuth 2.0 client to use when exchanging Wallet's token for a fresh access token, make sure
     * to configure it to use the correct [OAuth2KtorClient.clientAttestation].
     * @param internalTokenVerificationService Validates access tokens received in [validateAccessToken].
     * @param dpopNonceService Used to provide DPoP nonces for credential requests, which will be verified by
     * [internalTokenVerificationService].
     */
    @Deprecated(
        "Pass the app's HttpClient instead of engine, cookiesStorage and httpClientConfig, which oauth2Client " +
                "ignored when passed, and configure the OAuth 2.0 client with oauth2Client, clientAttestation and " +
                "verifyTokenIntrospectionJwt"
    )
    constructor(
        publicContext: String,
        engine: HttpClientEngine,
        cookiesStorage: CookiesStorage? = null,
        httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
        scope: CoroutineScope = CoroutineScope(Dispatchers.IO),
        @Suppress("DEPRECATION")
        oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
            engine = engine,
            cookiesStorage = cookiesStorage,
            httpClientConfig = httpClientConfig,
            oAuth2Client = OAuth2Client(),
        ),
        internalTokenVerificationService: TokenVerificationService,
        dpopNonceService: NonceService = DefaultNonceService(),
    ) : this(
        publicContext = publicContext,
        oauth2Client = oauth2Client,
        internalTokenVerificationService = internalTokenVerificationService,
        dpopNonceService = dpopNonceService,
        scope = scope,
    )

    private val _metadata: Deferred<OAuth2AuthorizationServerMetadata> by scope.lazyDeferred {
        oauth2Client.loadAuthorizationServerMetadata(publicContext)
    }

    override suspend fun metadata(): OAuth2AuthorizationServerMetadata = _metadata.await()

    override suspend fun getTokenInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenInfo> = catching {
        val oauthMetadata = _metadata.await()
        val token = authorizationHeader.let { if (it.contains(" ")) it.split(" ").last() else it }
        val request = TokenIntrospectionRequest(
            token = token,
            tokenTypeHint = authorizationHeader.split(" ").firstOrNull()
        )
        oauth2Client.callTokenIntrospection(
            oauthMetadata = oauthMetadata,
            request = request,
            popAudience = publicContext
        ).toTokenInfo(token)
    }

    /**
     * Obtains a JSON object representing [at.asitplus.openid.OidcUserInfo] from the Authorization Server,
     * where we need to exchange the the wallet's access token in [authorizationHeader] first
     * to get a valid access token to call the user info endpoint.
     */
    override suspend fun getUserInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject> = catching {
        val userInfoEndpoint = _metadata.await().userInfoEndpoint
            ?: throw InvalidToken("No UserInfo Endpoint found in Authorization Server metadata")
        val tokenResponse = oauth2Client.requestTokenWithTokenExchange(
            oauthMetadata = _metadata.await(),
            authorizationServer = publicContext,
            subjectToken = authorizationHeader.split(" ").last(),
            resource = userInfoEndpoint,
        ).getOrThrow()
        oauth2Client.requestUserInfo(userInfoEndpoint, tokenResponse.params)
    }

    override suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<ValidatedAccessToken> = catching {
        internalTokenVerificationService.validateAccessToken(
            tokenOrAuthHeader = authorizationHeader,
            httpRequest = httpRequest,
            dpopNonceService = dpopNonceService,
            validatedClientKey = null,
        ).getOrThrow()
    }

    override suspend fun getDpopNonce() = dpopNonceService.provideNonce()
}

private fun TokenIntrospectionResponse.toTokenInfo(token: String) = TokenInfo(
    token = token,
    scope = this.scope,
    authorizationDetails = this.authorizationDetails,
)
