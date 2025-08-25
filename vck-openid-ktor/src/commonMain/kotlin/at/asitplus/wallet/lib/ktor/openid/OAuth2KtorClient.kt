package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
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
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.header
import io.ktor.client.request.headers
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
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
    private val signClientAttestationPop: SignJwtFun<JsonWebToken>? = SignJwt(
        EphemeralKeyWithoutCert(),
        JwsHeaderNone()
    ),
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
        credentialIssuer: String,
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
            credentialIssuer = credentialIssuer
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
        credentialIssuer: String,
        state: String,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
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
            credentialIssuer = credentialIssuer,
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
            credentialIssuer = credentialIssuer,
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")
        tokenResponse
    }

    @Throws(Exception::class)
    private suspend fun postToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        tokenRequest: TokenRequestParameters,
        credentialIssuer: String,
    ): TokenResponseParameters {
        val tokenEndpointUrl = oauthMetadata.tokenEndpoint
            ?: throw Exception("No tokenEndpoint in $oauthMetadata")
        Napier.i("postToken: $tokenEndpointUrl with $tokenRequest")

        val clientAttestationJwt = if (oauthMetadata.useClientAuth()) {
            loadClientAttestationJwt?.invoke()
        } else null
        val clientAttestationPoPJwt =
            if (oauthMetadata.useClientAuth() && signClientAttestationPop != null && clientAttestationJwt != null) {
                BuildClientAttestationPoPJwt(
                    signClientAttestationPop,
                    clientId = oAuth2Client.clientId,
                    audience = credentialIssuer,
                    lifetime = 10.minutes,
                ).serialize()
            } else null
        val dpopHeader = if (oauthMetadata.hasMatchingDpopAlgorithm()) {
            BuildDPoPHeader(signDpop, url = tokenEndpointUrl)
        } else null

        return client.submitForm(
            url = tokenEndpointUrl,
            formParameters = parameters {
                tokenRequest.encodeToParameters<TokenRequestParameters>().forEach { append(it.key, it.value) }
            }
        ) {
            headers {
                clientAttestationJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttestationPoPJwt?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
                dpopHeader?.let { append(HttpHeaders.DPoP, it) }
            }
        }.body<TokenResponseParameters>()
    }

    private fun OAuth2AuthorizationServerMetadata.useClientAuth(): Boolean =
        tokenEndPointAuthMethodsSupported?.contains(OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true

    private fun OAuth2AuthorizationServerMetadata.hasMatchingDpopAlgorithm(): Boolean =
        dpopSigningAlgValuesSupported?.contains(dpopAlgorithm) == true


    /**
     * Builds the authorization request ([at.asitplus.openid.AuthenticationRequestParameters]) to start authentication at the
     * authorization server associated with the credential issuer.
     *
     * Prefers building the authn request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Uses Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) if advised
     * by the authorization server.
     *
     * Clients need to contiune the process (after getting back from the browser) with [requestTokenWithAuthCode].
     */
    @Throws(Exception::class)
    suspend fun startAuthorization(
        state: String = uuid4().toString(),
        credentialIssuer: String,
        issuerState: String? = null,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationDetails: Set<OpenIdAuthorizationDetails>?,
        scope: String?,
    ): OpenUrlForAuthnRequest {
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
                authRequest = authRequest,
                state = state,
                url = parEndpointUrl,
                credentialIssuer = credentialIssuer,
                tokenAuthMethods = oauthMetadata.tokenEndPointAuthMethodsSupported
            )
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequestAfterPar.encodeToParameters<AuthenticationRequestParameters>().forEach {
                    builder.parameters.append(it.key, it.value)
                }
            }.build().toString()
        } else {
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequest.encodeToParameters<AuthenticationRequestParameters>().forEach {
                    builder.parameters.append(it.key, it.value)
                }
                builder.parameters.append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }.build().toString()
        }
        Napier.i("Provisioning starts by returning URL to open: $authorizationUrl")
        return OpenUrlForAuthnRequest(authorizationUrl, state)
    }

    @Throws(Exception::class)
    private suspend fun pushAuthorizationRequest(
        authRequest: AuthenticationRequestParameters,
        state: String,
        url: String,
        credentialIssuer: String,
        tokenAuthMethods: Set<String>?,
    ): AuthenticationRequestParameters {
        val shouldIncludeClientAttestation =
            tokenAuthMethods?.contains(OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true
        val clientAttestationJwt = if (shouldIncludeClientAttestation) {
            loadClientAttestationJwt?.invoke()
        } else null
        val clientAttestationPoPJwt =
            if (shouldIncludeClientAttestation && signClientAttestationPop != null && clientAttestationJwt != null) {
                BuildClientAttestationPoPJwt(
                    signClientAttestationPop,
                    clientId = oAuth2Client.clientId,
                    audience = credentialIssuer,
                    lifetime = 10.minutes,
                ).serialize()
            } else null
        val response = client.submitForm(
            url = url,
            formParameters = parameters {
                authRequest.encodeToParameters().forEach { append(it.key, it.value) }
                append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }
        ) {
            headers {
                clientAttestationJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttestationPoPJwt?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
            }
        }.body<PushedAuthenticationResponseParameters>()
        if (response.errorDescription != null) {
            throw Exception(response.errorDescription)
        }
        if (response.error != null) {
            throw Exception(response.error)
        }
        if (response.requestUri == null) {
            throw Exception("No request_uri from PAR response at $url")
        }

        return AuthenticationRequestParameters(
            clientId = oAuth2Client.clientId,
            requestUri = response.requestUri,
            state = state,
        )
    }

}

val HttpHeaders.OAuthClientAttestation: String
    get() = "OAuth-Client-Attestation"

val HttpHeaders.OAuthClientAttestationPop: String
    get() = "OAuth-Client-Attestation-PoP"

val HttpHeaders.DPoP: String
    get() = "DPoP"

