package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2Client.AuthorizationForToken
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.cookies.CookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.header
import io.ktor.client.request.headers
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.http.headers
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import io.ktor.util.flattenEntries
import kotlin.time.Duration.Companion.minutes

/**
 * Implements the client side of OAuth2
 *
 * Supported features:
 *  * Token requests and responses
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 */
class OAuth2KtorClient(
    /** ktor engine to use to make requests to issuing service. */
    engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     */
    cookiesStorage: CookiesStorage? = null,
    /** Additional configuration for building the HTTP client, e.g. callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /**
     * Callback to load the client attestation JWT, which may be needed as authentication at the AS, where the
     * `clientId` must match [OAuth2Client.clientId] in [oAuth2Client] and the key attested in `cnf` must match
     * the key behind [signClientAttestationPop], see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
     */
    private val loadClientAttestationJwt: (suspend () -> String)? = null,
    /** Used for authenticating the client at the authorization server with client attestation. */
    private val signClientAttestationPop: SignJwtFun<JsonWebToken>? =
        SignJwt(EphemeralKeyWithoutCert(), JwsHeaderNone()),
    /** Used to calculate DPoP, i.e. the key the access token and refresh token gets bound to. */
    private val signDpop: SignJwtFun<JsonWebToken> = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()),
    private val dpopAlgorithm: JwsAlgorithm = JwsAlgorithm.Signature.ES256,
    /**
     * Implements OAuth2 protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works
     */
    val oAuth2Client: OAuth2Client,
) {

    private val client: HttpClient = HttpClient(engine) {
        followRedirects = false
        install(ContentNegotiation) {
            json(vckJsonSerializer)
        }
        install(DefaultRequest.Plugin) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }
        httpClientConfig?.let { apply(it) }
        install(HttpCookies.Companion) {
            cookiesStorage?.let {
                storage = it
            }
        }
    }

    /**
     * Open the [url] in a browser (so the user can authenticate at the AS), and store [state] to use in next call.
     */
    data class OpenUrlForAuthnRequest(
        val url: String,
        val state: String,
    )

    /**
     * Uses a pre-authorized code from the authorization server to request an access token.
     */
    suspend fun requestTokenWithPreAuthorizedCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        preAuthorizedCode: String,
        transactionCode: String?,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("requestTokenWithPreAuthorizedCode")
        val state = uuid4().toString()

        val hasScope = scope != null
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                state = state,
                authorization = AuthorizationForToken.PreAuthCode(preAuthorizedCode, transactionCode),
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer
        )
        Napier.i("Received token response")
        Napier.d("Received token response: $tokenResponse")
        tokenResponse
    }

    /**
     * Uses the auth code to request an access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * @param url the URL as it has been redirected back from the authorization server, i.e. containing param `code`
     */
    suspend fun requestTokenWithAuthCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        url: String,
        authorizationServer: String,
        state: String,
        scope: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("resumeWithAuthCode")
        Napier.d("resumeWithAuthCode: $url")

        val authnResponse = Url(url).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationResponseParameters>()
        val code = authnResponse.code
            ?: throw Exception("No authn code in $url")

        val hasScope = scope != null
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.Code(code),
                state = state,
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer,
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")
        tokenResponse
    }

    /**
     * Uses the refresh token to request a new access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     */
    suspend fun requestTokenWithRefreshToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        credentialIssuer: String,
        refreshToken: String,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("refreshCredential")
        Napier.d("refreshCredential: $refreshToken")
        val hasScope = scope != null
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.RefreshToken(refreshToken),
                state = null,
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = credentialIssuer,
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")
        tokenResponse
    }

    /**
     * Uses an access token from another client to request a new access token,
     * see [RFC8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).
     */
    suspend fun requestTokenWithTokenExchange(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        subjectToken: String,
        resource: String?,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("requestTokenWithTokenExchange")
        Napier.d("requestTokenWithTokenExchange: $subjectToken")
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.TokenExchange(subjectToken),
                state = null,
                scope = "${OpenIdConstants.SCOPE_OPENID} ${OpenIdConstants.SCOPE_PROFILE}",
                authorizationDetails = null,
                resource = resource,
            ),
            popAudience = authorizationServer
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")
        tokenResponse
    }

    @Throws(Exception::class)
    private suspend fun postToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        tokenRequest: TokenRequestParameters,
        popAudience: String,
    ): TokenResponseParameters {
        val tokenEndpointUrl = oauthMetadata.tokenEndpoint
            ?: throw Exception("No tokenEndpoint in $oauthMetadata")
        Napier.i("postToken: $tokenEndpointUrl with $tokenRequest")
        return client.request {
            url(tokenEndpointUrl)
            method = HttpMethod.Post
            setBody(FormDataContent(parameters {
                tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
            }))
            applyAuthnForToken(oauthMetadata, popAudience, tokenEndpointUrl, HttpMethod.Post, true)()
        }.body<TokenResponseParameters>()
    }

    /**
     * Builds the authorization request ([AuthenticationRequestParameters]) to start authentication at the
     * authorization server.
     *
     * Prefers building the authn request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Uses Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) if advised
     * by the authorization server.
     *
     * Clients need to continue the process (after getting back from the browser) with [requestTokenWithAuthCode].
     */
    @Throws(Exception::class)
    suspend fun startAuthorization(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        state: String = uuid4().toString(),
        issuerState: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
        scope: String? = null,
    ) = catching {
        val authorizationEndpointUrl = oauthMetadata.authorizationEndpoint
            ?: throw Exception("no authorizationEndpoint in $oauthMetadata")
        val wrapAsJar =
            oauthMetadata.requestObjectSigningAlgorithmsSupported?.contains(JwsAlgorithm.Signature.ES256) == true
        val authRequest = oAuth2Client.createAuthRequest(
            state = state,
            authorizationDetails = if (scope == null) authorizationDetails else null,
            issuerState = issuerState,
            scope = scope,
            wrapAsJar = wrapAsJar
        )
        val requiresPar = oauthMetadata.requirePushedAuthorizationRequests == true
        val parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint
        val authorizationUrl = if (parEndpointUrl != null && requiresPar) {
            val authRequestAfterPar = pushAuthorizationRequest(
                oauthMetadata = oauthMetadata,
                authRequest = authRequest,
                state = state,
                popAudience = authorizationServer,
            )
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequestAfterPar.encodeToParameters().forEach {
                    builder.parameters.append(it.key, it.value)
                }
            }.build().toString()
        } else {
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequest.encodeToParameters().forEach {
                    builder.parameters.append(it.key, it.value)
                }
                builder.parameters.append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }.build().toString()
        }
        Napier.i("Provisioning starts by returning URL to open: $authorizationUrl")
        OpenUrlForAuthnRequest(authorizationUrl, state)
    }

    @Throws(Exception::class)
    private suspend fun pushAuthorizationRequest(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authRequest: AuthenticationRequestParameters,
        state: String,
        popAudience: String,
    ): AuthenticationRequestParameters {
        val parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint
            ?: throw Exception("No pushedAuthorizationRequestEndpoint in $oauthMetadata")

        val response = client.request {
            url(parEndpointUrl)
            method = HttpMethod.Post
            setBody(FormDataContent(parameters {
                authRequest.encodeToParameters().forEach { append(it.key, it.value) }
                append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }))
            applyAuthnForToken(oauthMetadata, popAudience, parEndpointUrl, HttpMethod.Post, false)()
        }.body<PushedAuthenticationResponseParameters>()

        if (response.errorDescription != null) {
            throw Exception(response.errorDescription)
        }
        if (response.error != null) {
            throw Exception(response.error)
        }
        if (response.requestUri == null) {
            throw Exception("No request_uri from PAR response at $parEndpointUrl")
        }

        return AuthenticationRequestParameters(
            clientId = oAuth2Client.clientId,
            requestUri = response.requestUri,
            state = state,
        )
    }

    /**
     * Sets the appropriate headers when accessing [resourceUrl], by reading data from [tokenResponse],
     * i.e. [HttpHeaders.Authorization] and probably [HttpHeaders.DPoP].
     */
    suspend fun applyToken(
        tokenResponse: TokenResponseParameters,
        resourceUrl: String,
        httpMethod: HttpMethod,
    ): HttpRequestBuilder.() -> Unit {
        val dpopHeader = if (tokenResponse.tokenType.equals(TOKEN_TYPE_DPOP, true))
            BuildDPoPHeader(
                signDpop = signDpop,
                url = resourceUrl,
                accessToken = tokenResponse.accessToken,
                httpMethod = httpMethod.value
            )
        else null
        return {
            headers {
                append(HttpHeaders.Authorization, tokenResponse.toHttpHeaderValue())
                dpopHeader?.let { append(HttpHeaders.DPoP, it) }
            }
        }
    }

    /**
     * Sets the appropriate headers when accessing a token endpoint,
     * i.e., performs client authentication.
     */
    suspend fun applyAuthnForToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        popAudience: String,
        resourceUrl: String,
        httpMethod: HttpMethod,
        useDpop: Boolean,
    ): HttpRequestBuilder.() -> Unit {
        val clientAttestationJwt = if (oauthMetadata.useClientAuth()) {
            loadClientAttestationJwt?.invoke()
        } else null
        val clientAttestationPoPJwt =
            if (oauthMetadata.useClientAuth() && signClientAttestationPop != null && clientAttestationJwt != null) {
                BuildClientAttestationPoPJwt(
                    signClientAttestationPop,
                    clientId = oAuth2Client.clientId,
                    audience = popAudience,
                    lifetime = 10.minutes,
                ).serialize()
            } else null

        val dpopHeader = if (oauthMetadata.hasMatchingDpopAlgorithm() && useDpop) {
            BuildDPoPHeader(signDpop = signDpop, url = resourceUrl, httpMethod = httpMethod.value)
        } else null

        return {
            headers {
                clientAttestationJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttestationPoPJwt?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
                dpopHeader?.let { append(HttpHeaders.DPoP, it) }
            }
        }
    }

    private fun OAuth2AuthorizationServerMetadata.useClientAuth(): Boolean =
        tokenEndPointAuthMethodsSupported?.contains(OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true

    private fun OAuth2AuthorizationServerMetadata.hasMatchingDpopAlgorithm(): Boolean =
        dpopSigningAlgValuesSupported?.contains(dpopAlgorithm) == true
}

val HttpHeaders.OAuthClientAttestation: String
    get() = "OAuth-Client-Attestation"

val HttpHeaders.OAuthClientAttestationPop: String
    get() = "OAuth-Client-Attestation-PoP"

val HttpHeaders.DPoP: String
    get() = "DPoP"

