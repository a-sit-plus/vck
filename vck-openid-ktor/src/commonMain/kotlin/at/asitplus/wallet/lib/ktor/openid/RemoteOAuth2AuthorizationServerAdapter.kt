package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.WellKnownPaths
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2Utils.insertWellKnownPath
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.TokenInfo
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.serialization.json.JsonObject

/**
 * Uses an external OAuth 2.0 Authorization Server with a [at.asitplus.wallet.lib.oidvci.CredentialIssuer],
 * i.e., delegate authorization to the external AS, and load user info from there
 * (after performing token exchange with the Wallet's access token to get a fresh one).
 * Make sure to configure [oauth2Client] to use the correct [OAuth2KtorClient.loadInstanceAttestation].
 */
class RemoteOAuth2AuthorizationServerAdapter(
    /** Base URL of the remote Authorization Server. */
    override val publicContext: String,
    /** ktor engine to make requests to the verifier. */
    private val engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     */
    private val cookiesStorage: CookiesStorage? = null,
    /** Additional configuration for building the HTTP client, e.g., callers may enable logging. */
    private val httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /** [CoroutineScope] to fetch the authorization server's metadata. */
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO),
    /** OAuth 2.0 client to use when exchanging Wallet's token for a fresh access token. */
    private val oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
        engine = engine,
        cookiesStorage = cookiesStorage,
        httpClientConfig = httpClientConfig,
        oAuth2Client = OAuth2Client(),
    ),
    /** Validates access tokens received in [validateAccessToken]. */
    val internalTokenVerificationService: TokenVerificationService,
    /** Used to provide DPoP nonces for credential requests, which will be verified by [internalTokenVerificationService]. */
    val dpopNonceService: NonceService = DefaultNonceService(),
) : OAuth2AuthorizationServerAdapter {

    private val _metadata: Deferred<OAuth2AuthorizationServerMetadata> by scope.lazyDeferred {
        catching { loadOauthASMetadata() }
            .getOrElse { loadOpenidConfiguration() }
    }

    private suspend fun loadOauthASMetadata() =
        oauth2Client.client.get(insertWellKnownPath(publicContext, WellKnownPaths.OauthAuthorizationServer))
            .body<OAuth2AuthorizationServerMetadata>()

    private suspend fun loadOpenidConfiguration() =
        oauth2Client.client.get(insertWellKnownPath(publicContext, WellKnownPaths.OpenidConfiguration))
            .body<OAuth2AuthorizationServerMetadata>()

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
            token = token,
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
        oauth2Client.requestTokenWithTokenExchange(
            oauthMetadata = _metadata.await(),
            authorizationServer = publicContext,
            subjectToken = authorizationHeader.split(" ").last(),
            resource = userInfoEndpoint,
        ).getOrThrow().let {
            fetchUserInfo(userInfoEndpoint, it.params, it.dpopNonce)
        }
    }

    private suspend fun fetchUserInfo(
        userInfoEndpoint: String,
        params: TokenResponseParameters,
        dpopNonce: String?,
        retryCount: Int = 0,
    ): JsonObject = try {
        oauth2Client.client.request {
            url(userInfoEndpoint)
            method = HttpMethod.Get
            oauth2Client.applyToken(params, userInfoEndpoint, HttpMethod.Get, dpopNonce)()
        }.body()
    } catch (error: HttpErrorResponseException) {
        error.dpopNonce()
            ?.takeIf { retryCount == 0 }
            ?.let { fetchUserInfo(userInfoEndpoint, params, it, retryCount + 1) }
            ?: throw error
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
