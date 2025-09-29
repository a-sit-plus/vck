package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.RandomSource
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
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import io.ktor.utils.io.*
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
    /** Source for random bytes, i.e., nonces for proof-of-possession of key material for sender-constrained tokens. */
    private val randomSource: RandomSource = RandomSource.Secure,
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
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        Napier.i("requestTokenWithPreAuthorizedCode")
        val state = uuid4().toString()
        val hasScope = scope != null
        postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                state = state,
                authorization = AuthorizationForToken.PreAuthCode(preAuthorizedCode, transactionCode),
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer
        ).also {
            Napier.i("Received token response")
            Napier.d("Received token response: $it")
        }
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
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        Napier.i("requestTokenWithAuthCode")
        Napier.d("requestTokenWithAuthCode: $url")

        val authnResponse = Url(url).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationResponseParameters>()
        val code = authnResponse.code
            ?: throw Exception("No authn code in $url")

        val hasScope = scope != null
        postToken(
            oauthMetadata = oauthMetadata,
            tokenRequest = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.Code(code),
                state = state,
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer,
        ).also {
            Napier.i("Received token response")
            Napier.d("Received token response $it")
        }
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
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
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
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
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

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun postToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        tokenRequest: TokenRequestParameters,
        popAudience: String,
        dpopNonce: String? = null,
        retryCount: Int = 0,
    ): TokenResponseWithDpopNonce = oauthMetadata.tokenEndpoint?.let { tokenEndpointUrl ->
        Napier.i("postToken: $tokenEndpointUrl with $tokenRequest")
        client.request {
            url(tokenEndpointUrl)
            method = HttpMethod.Post
            setBody(FormDataContent(parameters {
                tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
            }))
            applyAuthnForToken(oauthMetadata, popAudience, tokenEndpointUrl, HttpMethod.Post, true, dpopNonce)()
        }.onFailure { response ->
            dpopNonce(response)?.takeIf { retryCount == 0 }?.let { dpopNonce ->
                postToken(oauthMetadata, tokenRequest, popAudience, dpopNonce, retryCount + 1)
            } ?: throw Exception("Error requesting Token: ${errorDescription ?: error}")
        }.onSuccessToken { response ->
            TokenResponseWithDpopNonce(this, response.headers[HttpHeaders.DPoPNonce])
        }
    } ?: throw IllegalArgumentException("No tokenEndpoint in $oauthMetadata")

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
        val authRequest = if (wrapAsJar) oAuth2Client.createAuthRequestJar(
            state = state,
            authorizationDetails = if (scope == null) authorizationDetails else null,
            issuerState = issuerState,
            scope = scope,
        ) else oAuth2Client.createAuthRequest(
            state = state,
            authorizationDetails = if (scope == null) authorizationDetails else null,
            issuerState = issuerState,
            scope = scope,
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
                    // TODO check if it now contains type
                    builder.parameters.append(it.key, it.value)
                }
                builder.parameters.append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }.build().toString()
        }
        Napier.i("Provisioning starts by returning URL to open: $authorizationUrl")
        OpenUrlForAuthnRequest(authorizationUrl, state)
    }

    private suspend fun pushAuthorizationRequest(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authRequest: RequestParameters,
        state: String,
        popAudience: String,
        dpopNonce: String? = null,
        retryCount: Int = 0,
    ): JarRequestParameters = oauthMetadata.pushedAuthorizationRequestEndpoint?.let { parEndpointUrl ->
        client.request {
            url(parEndpointUrl)
            method = HttpMethod.Post
            setBody(FormDataContent(parameters {
                authRequest.encodeToParameters().forEach { append(it.key, it.value) }
                append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }))
            applyAuthnForToken(oauthMetadata, popAudience, parEndpointUrl, HttpMethod.Post, false, dpopNonce)()
        }.onFailure { response ->
            dpopNonce(response)?.takeIf { retryCount == 0 }?.let { dpopNonce ->
                pushAuthorizationRequest(oauthMetadata, authRequest, state, popAudience, dpopNonce, retryCount + 1)
            } ?: throw Exception("Error requesting PAR: ${errorDescription ?: error}")
        }.onSuccessPar {
            JarRequestParameters(
                clientId = oAuth2Client.clientId,
                requestUri = requestUri ?: throw Exception("No request_uri from PAR response at $parEndpointUrl"),
                state = state,
            )
        }
    } ?: throw Exception("No pushedAuthorizationRequestEndpoint in $oauthMetadata")

    /**
     * Sets the appropriate headers when accessing [resourceUrl], by reading data from [tokenResponse],
     * i.e. [HttpHeaders.Authorization] and probably [HttpHeaders.DPoP].
     */
    suspend fun applyToken(
        tokenResponse: TokenResponseParameters,
        resourceUrl: String,
        httpMethod: HttpMethod,
        dpopNonce: String? = null,
    ): HttpRequestBuilder.() -> Unit {
        val dpopHeader = if (tokenResponse.tokenType.equals(TOKEN_TYPE_DPOP, true))
            BuildDPoPHeader(
                signDpop = signDpop,
                url = resourceUrl,
                httpMethod = httpMethod.value,
                accessToken = tokenResponse.accessToken,
                nonce = dpopNonce,
                randomSource = randomSource
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
     * i.e., performs client authentication, also sign DPoP proof when [useDpop] is set.
     */
    suspend fun applyAuthnForToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        popAudience: String,
        resourceUrl: String,
        httpMethod: HttpMethod,
        useDpop: Boolean,
        dpopNonce: String? = null,
    ): HttpRequestBuilder.() -> Unit {
        val (clientAttJwt, clientAttPop) = oauthMetadata.useClientAuth().takeIf { it }?.let {
            loadClientAttestationJwt?.invoke()?.let { clientAttestationJwt ->
                clientAttestationJwt to signClientAttestationPop?.let {
                    BuildClientAttestationPoPJwt(
                        signClientAttestationPop,
                        clientId = oAuth2Client.clientId,
                        audience = popAudience,
                        lifetime = 10.minutes,
                    ).serialize()
                }
            }
        } ?: (null to null)

        val dpopHeader = oauthMetadata.hasMatchingDpopAlgorithm().takeIf { it && useDpop }?.let {
            BuildDPoPHeader(
                signDpop = signDpop,
                url = resourceUrl,
                httpMethod = httpMethod.value,
                nonce = dpopNonce,
                randomSource = randomSource,
            )
        }

        return {
            headers {
                clientAttJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttPop?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
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

val HttpHeaders.DPoPNonce: String
    get() = "DPoP-Nonce"


data class TokenResponseWithDpopNonce(
    val params: TokenResponseParameters,
    val dpopNonce: String?,
)

private suspend inline fun <R> IntermediateResult<R>.onSuccessPar(
    block: PushedAuthenticationResponseParameters.(httpResponse: HttpResponse) -> R,
) = onSuccess<PushedAuthenticationResponseParameters, R>(block)

private suspend inline fun <R> IntermediateResult<R>.onSuccessToken(
    block: TokenResponseParameters.(httpResponse: HttpResponse) -> R,
) = onSuccess<TokenResponseParameters, R>(block)