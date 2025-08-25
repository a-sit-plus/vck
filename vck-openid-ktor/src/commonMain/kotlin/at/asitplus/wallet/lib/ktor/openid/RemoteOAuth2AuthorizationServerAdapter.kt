package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION
import at.asitplus.openid.OpenIdConstants.TOKEN_PREFIX_DPOP
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject

/**
 * Uses an external OAuth 2.0 Authorization Server with a [at.asitplus.wallet.lib.oidvci.CredentialIssuer],
 * i.e., delegate authorization to the external AS, and load user info from there
 * (after performing token exchange with the Wallet's access token to get a fresh one).
 * Make sure to configure [oauth2Client] to use the correct [OAuth2KtorClient.loadClientAttestationJwt].
 */
class RemoteOAuth2AuthorizationServerAdapter(
    /** Base URL of the remote Authorization Server. */
    override val publicContext: String,
    /** ktor engine to make requests to the verifier. */
    engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     */
    cookiesStorage: CookiesStorage? = null,
    /** Additional configuration for building the HTTP client, e.g., callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /** [CoroutineScope] to fetch the authorization server's metadata. */
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO),
    /** OAuth 2.0 client to use when exchanging Wallet's token for a fresh access token. */
    private val oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
        engine = engine,
        cookiesStorage = cookiesStorage,
        httpClientConfig = httpClientConfig,
        oAuth2Client = OAuth2Client(),
    ),
) : OAuth2AuthorizationServerAdapter {

    private val client: HttpClient = HttpClient(engine) {
        followRedirects = false
        install(ContentNegotiation) {
            json(vckJsonSerializer)
        }
        install(DefaultRequest.Plugin) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }
        httpClientConfig?.let { apply(it) }
    }

    private val _metadata: Deferred<OAuth2AuthorizationServerMetadata> by scope.lazyDeferred {
        catching {
            client.get("$publicContext$PATH_WELL_KNOWN_OPENID_CONFIGURATION")
                .body<OAuth2AuthorizationServerMetadata>()
        }.getOrElse {
            client.get("$publicContext$PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER")
                .body<OAuth2AuthorizationServerMetadata>()
        }
    }

    @Deprecated("Use [validateTokenExtractUser] instead")
    override val tokenVerificationService: TokenVerificationService
        get() = object : TokenVerificationService {
            override suspend fun validateRefreshToken(
                refreshToken: String,
                request: RequestInfo?,
            ): String {
                TODO("Not yet implemented")
            }

            override suspend fun validateTokenExtractUser(
                authorizationHeader: String,
                request: RequestInfo?,
            ): ValidatedAccessToken {
                TODO("Not yet implemented")
            }

            override suspend fun validateTokenForTokenExchange(
                subjectToken: String,
            ): ValidatedAccessToken {
                TODO("Not yet implemented")
            }
        }

    @Deprecated("Use [metadata()] instead")
    override val metadata: OAuth2AuthorizationServerMetadata by lazy {
        runBlocking {
            _metadata.await()
        }
    }

    override suspend fun metadata(): OAuth2AuthorizationServerMetadata = _metadata.await()

    override suspend fun userInfo(
        authorizationHeader: String,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        request: RequestInfo?,
    ): KmmResult<JsonObject> = catching {
        val userInfoEndpoint = _metadata.await().userInfoEndpoint
            ?: throw InvalidToken("No UserInfo Endpoint found in Authorization Server metadata")
        if (authorizationHeader.startsWith(TOKEN_TYPE_BEARER, ignoreCase = true)) {
            callUserInfo(userInfoEndpoint, authorizationHeader)
        } else if (authorizationHeader.startsWith(TOKEN_TYPE_DPOP, ignoreCase = true)) {
            // TODO Validate the DPoP from the client!
            oauth2Client.requestTokenWithTokenExchange(
                oauthMetadata = _metadata.await(),
                authorizationServer = publicContext,
                subjectToken = authorizationHeader.substringAfter(TOKEN_PREFIX_DPOP).trim(),
                resource = userInfoEndpoint,
            ).getOrThrow().let {
                callUserInfo(userInfoEndpoint, it.toHttpHeaderValue(), it)
            }
        } else {
            throw InvalidToken("authorization header not valid: $authorizationHeader")
        }
    }

    private suspend fun callUserInfo(
        userInfoEndpoint: String,
        authorizationHeader: String,
        tokenResponseParameters: TokenResponseParameters? = null,
    ): JsonObject = client.request {
        url(userInfoEndpoint)
        method = HttpMethod.Get
        tokenResponseParameters?.let { oauth2Client.applyToken(it, userInfoEndpoint, HttpMethod.Get)() }
            ?: header(HttpHeaders.Authorization, authorizationHeader)
    }.body<JsonObject>()

}