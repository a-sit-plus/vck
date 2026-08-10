package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenIntrospectionJwtResponse
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oauth2.DPoP
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2Client.AuthorizationForToken
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuthClientAttestationPop
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import at.asitplus.wallet.lib.oidvci.TokenInfo
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.*
import io.ktor.utils.io.*
import kotlin.time.Duration

/**
 * Implements the client side of OAuth2
 *
 * Supported features:
 *  * Token requests and responses
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 *  * [JSON Web Token (JWT) Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)
 *  * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
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
    /** Used to prove possession of the key material for the instance attestation. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Used to calculate DPoP, i.e. the key the access token and refresh token gets bound to.**/
    private val signDpop: SignJwtFun<JsonWebToken> = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()),
    /**
     * Implements OAuth2 protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works
     */
    val oAuth2Client: OAuth2Client,
    /** Source for random bytes, i.e., nonces for proof-of-possession of key material for sender-constrained tokens. */
    private val randomSource: RandomSource = RandomSource.Secure,
    /** Verifies signed token introspection responses. By default, every syntactically valid JWS is accepted. */
    private val verifyTokenIntrospectionJwt: suspend (JwsCompactTyped<TokenIntrospectionResponse>) -> Boolean = { true },
    /**
     * Return a new Wallet Instance Attestation (WIA) to authenticate the Wallet App to the
     * Authorization Service with OAuth Attestation Based Client Auth.
     * Returned JWT MUST reference [keyMaterial] in [JsonWebToken.confirmationClaim].
     */
    val loadInstanceAttestation: (suspend (LoadInstanceAttestationInput) -> KmmResult<JwsCompactTyped<JsonWebToken>>)? = null,
) {

    /** Used in [OAuth2KtorClient.loadInstanceAttestation] to provide information about the authorization server. */
    data class LoadInstanceAttestationInput(
        /** Value from [OAuth2AuthorizationServerMetadata.issuer] */
        val authorizationServer: String,
        /** Value from [at.asitplus.openid.IssuerMetadata.credentialIssuer] */
        val credentialIssuer: String,
        /**
         * Value from [at.asitplus.openid.IssuerMetadata.preferredClientStatusPeriod].
         * If the field is present then the Wallet Unit SHALL send the WIA available to them with
         * `(client_status.exp - current time) - preferred_client_status_period` as small as possible but non-negative.
         * If no such WIA is available to the Wallet Unit, it SHALL request a new WIA from the Wallet Provider that
         * satisfies `client_status.exp - current time >= preferred_client_status_period.` */
        val preferredClientStatusPeriod: Duration?,
    )

    // TODO: Also need to store challenge from Attestation-Based Client Auth

    /**
     * Stores the latest DPoP nonce per origin. RFC 9449 requires using only the most recent nonce
     * issued by the server that provided it.
     */
    private val dpopNonceByContext: MutableMap<String, String> = mutableMapOf()

    private fun String.dpopContext(): String = Url(this).let { parsed ->
        "${parsed.protocol.name}://${parsed.host}:${parsed.port}"
    }

    private fun currentDpopNonce(url: String): String? = dpopNonceByContext[url.dpopContext()]

    private fun updateDpopNonce(url: String, nonce: String?): String? =
        nonce?.takeIf { it.isNotBlank() }?.let { dpopNonceByContext[url.dpopContext()] = nonce; nonce }

    internal val client = buildHttpClient(engine, cookiesStorage, httpClientConfig)

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
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        Napier.i("requestTokenWithPreAuthorizedCode")
        val state = uuid4().toString()
        val hasScope = scope != null
        postToken(
            oauthMetadata = oauthMetadata,
            request = oAuth2Client.createTokenRequestParameters(
                state = state,
                authorization = AuthorizationForToken.PreAuthCode(preAuthorizedCode, transactionCode),
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer,
            issuerMetadata = issuerMetadata,
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
        issuerMetadata: IssuerMetadata? = null,
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
            request = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.Code(code),
                state = state,
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = authorizationServer,
            issuerMetadata = issuerMetadata,
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
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        Napier.i("refreshCredential")
        Napier.d("refreshCredential: $refreshToken")
        val hasScope = scope != null
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            request = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.RefreshToken(refreshToken),
                state = null,
                scope = scope,
                authorizationDetails = if (!hasScope) authorizationDetails else null
            ),
            popAudience = oauthMetadata.issuer,
            issuerMetadata = issuerMetadata,
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
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        Napier.i("requestTokenWithTokenExchange")
        Napier.d("requestTokenWithTokenExchange: $subjectToken")
        val tokenResponse = postToken(
            oauthMetadata = oauthMetadata,
            request = oAuth2Client.createTokenRequestParameters(
                authorization = AuthorizationForToken.TokenExchange(subjectToken),
                state = null,
                scope = "${OpenIdConstants.SCOPE_OPENID} ${OpenIdConstants.SCOPE_PROFILE}",
                authorizationDetails = null,
                resource = resource,
            ),
            popAudience = authorizationServer,
            issuerMetadata = issuerMetadata,
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")
        tokenResponse
    }

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun postToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        request: TokenRequestParameters,
        popAudience: String,
        retryCount: Int = 0,
        issuerMetadata: IssuerMetadata? = null
    ): TokenResponseWithDpopNonce = oauthMetadata.tokenEndpoint?.let { url ->
        Napier.i("postToken: $url with $request")
        val response = try {
            client.request {
                url(url)
                method = HttpMethod.Post
                setBody(FormDataContent(parameters {
                    request.encodeToParameters().forEach { append(it.key, it.value) }
                }))
                applyAuthnForToken(
                    resourceUrl = url,
                    httpMethod = HttpMethod.Post,
                    useDpop = true,
                    authorizationServer = popAudience,
                    oauthMetadata = oauthMetadata,
                    issuerMetadata = issuerMetadata,
                )()
            }
        } catch (error: HttpErrorResponseException) {
            return@let error.updateDpopNonceAndRetry(url, retryCount) {
                postToken(oauthMetadata, request, popAudience, retryCount + 1, issuerMetadata)
            }
        }
        val dpopNonce = response.dpopNonce
        updateDpopNonce(url, dpopNonce)
        TokenResponseWithDpopNonce(response.body(), dpopNonce)
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
        issuerMetadata: IssuerMetadata? = null
    ) = catching {
        val authorizationEndpointUrl = oauthMetadata.authorizationEndpoint
            ?: throw Exception("no authorizationEndpoint in $oauthMetadata")
        val requiresPar = oauthMetadata.requirePushedAuthorizationRequests == true
        val parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint
        if (requiresPar)
            require(parEndpointUrl != null) { "PAR required, but pushedAuthorizationRequestEndpoint is null" }
        // use PAR when available, in accordance with OpenID4VCI HAIP
        val usePar = parEndpointUrl != null || requiresPar

        val requiresJar = oauthMetadata.requireSignedRequestObject == true
        val supportsJar = oauthMetadata.requestObjectSigningAlgorithmsSupported.supportsEs256()
        if (requiresJar)
            require(supportsJar) { "JAR required, but requestObjectSigningAlgorithmsSupported does not support ES256" }
        // use JAR when required, or when it's not PAR (because then it doesn't increase security)
        val useJar = requiresJar || (supportsJar && !usePar)

        val authRequest = if (useJar)
            oAuth2Client.createAuthRequestJar(
                state = state,
                authorizationDetails = if (scope == null) authorizationDetails else null,
                issuerState = issuerState,
                scope = scope,
            )
        else
            oAuth2Client.createAuthRequest(
                state = state,
                authorizationDetails = if (scope == null) authorizationDetails else null,
                issuerState = issuerState,
                scope = scope,
            )

        val authorizationUrl = if (usePar)
            URLBuilder(authorizationEndpointUrl).also { builder ->
                pushAuthorizationRequest(
                    oauthMetadata = oauthMetadata,
                    authRequest = authRequest,
                    state = state,
                    popAudience = authorizationServer,
                    issuerMetadata = issuerMetadata,
                ).encodeToParameters().forEach {
                    builder.parameters.append(it.key, it.value)
                }
            }.build().toString()
        else
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequest.encodeToParameters().forEach {
                    builder.parameters.append(it.key, it.value)
                }
                builder.parameters.append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
            }.build().toString()
        Napier.i("Provisioning starts by returning URL to open: $authorizationUrl")
        OpenUrlForAuthnRequest(authorizationUrl, state)
    }

    private fun Set<JwsAlgorithm>?.supportsEs256(): Boolean =
        this?.contains(JwsAlgorithm.Signature.ES256) == true

    private suspend fun pushAuthorizationRequest(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authRequest: RequestParameters,
        state: String,
        popAudience: String,
        retryCount: Int = 0,
        issuerMetadata: IssuerMetadata? = null
    ): JarRequestParameters = oauthMetadata.pushedAuthorizationRequestEndpoint?.let { url ->
        val response = try {
            client.request {
                url(url)
                method = HttpMethod.Post
                setBody(FormDataContent(parameters {
                    authRequest.encodeToParameters().forEach { append(it.key, it.value) }
                    append(OpenIdConstants.PARAMETER_PROMPT, OpenIdConstants.PARAMETER_PROMPT_LOGIN)
                }))
                applyAuthnForToken(
                    resourceUrl = url,
                    httpMethod = HttpMethod.Post,
                    useDpop = true,
                    authorizationServer = popAudience,
                    oauthMetadata = oauthMetadata,
                    issuerMetadata = issuerMetadata,
                )()
            }
        } catch (error: HttpErrorResponseException) {
            return@let error.updateDpopNonceAndRetry(url, retryCount) {
                pushAuthorizationRequest(oauthMetadata, authRequest, state, popAudience, retryCount + 1, issuerMetadata)
            }
        }
        updateDpopNonce(url, response.dpopNonce)
        JarRequestParameters(
            clientId = oAuth2Client.clientId,
            requestUri = response.body<PushedAuthenticationResponseParameters>().requestUri
                ?: throw Exception("No request_uri from PAR response at $url"),
        )
    } ?: throw Exception("No pushedAuthorizationRequestEndpoint in $oauthMetadata")

    /**
     * Calls the token introspection endpoint ([OAuth2AuthorizationServerMetadata.introspectionEndpoint])
     * to check whether the given token is active, returns [TokenInfo] on success, otherwise throws [InvalidToken].
     */
    suspend fun callTokenIntrospection(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        request: TokenIntrospectionRequest,
        token: String,
        popAudience: String,
        retryCount: Int = 0,
        issuerMetadata: IssuerMetadata? = null,
    ): TokenIntrospectionResponse = oauthMetadata.introspectionEndpoint?.let { url ->
        Napier.i("callTokenIntrospection: $url with $request")
        val response = try {
            client.request {
                url(url)
                method = HttpMethod.Post
                setBody(FormDataContent(parameters {
                    request.encodeToParameters().forEach { append(it.key, it.value) }
                }))
                applyAuthnForToken(
                    resourceUrl = url,
                    httpMethod = HttpMethod.Post,
                    useDpop = true,
                    authorizationServer = popAudience,
                    oauthMetadata = oauthMetadata,
                    issuerMetadata = issuerMetadata,
                )()
            }
        } catch (error: HttpErrorResponseException) {
            return@let error.updateDpopNonceAndRetry(url, retryCount) {
                callTokenIntrospection(oauthMetadata, request, token, popAudience, retryCount + 1)
            }
        }
        updateDpopNonce(url, response.dpopNonce)
        parseTokenIntrospectionResponse(
            body = response.bodyAsText(),
            verifyTokenIntrospectionJwt = verifyTokenIntrospectionJwt,
            requestedResponseFormat = request.responseFormat,
        ).also {
            if (!it.active) {
                throw InvalidToken("Introspected token is not active")
            }
        }
    } ?: throw InvalidToken("No introspection endpoint found in Authorization Server metadata")

    /** Store the DPoP nonce if it is set, and retry the previous action */
    private suspend fun <T> HttpErrorResponseException.updateDpopNonceAndRetry(
        url: String,
        retryCount: Int,
        action: suspend () -> T
    ): T = dpopNonce()
        ?.let { updateDpopNonce(url, it) }
        ?.takeIf { retryCount == 0 }
        ?.let { action() }
        ?: throw this

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
                nonce = dpopNonce ?: currentDpopNonce(resourceUrl),
                randomSource = randomSource
            )
        else null
        return {
            headers {
                append(HttpHeaders.Authorization, tokenResponse.toHttpHeaderValue())
                dpopHeader?.let { append(HttpHeaders.DPoP, it.toString()) }
            }
        }
    }

    /**
     * Sets the appropriate headers when accessing a token endpoint:
     * - loads client attestation when [loadInstanceAttestation] is set
     * - sends a DPoP proof when [useDpop] is set
     */
    internal suspend fun applyAuthnForToken(
        resourceUrl: String,
        httpMethod: HttpMethod,
        useDpop: Boolean,
        authorizationServer: String,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpRequestBuilder.() -> Unit {
        val (clientAttJwt, clientAttPop) = if (loadInstanceAttestation != null && oauthMetadata.supportsClientAuth()) {
            val wia = loadInstanceAttestation.invoke(
                LoadInstanceAttestationInput(
                    authorizationServer = authorizationServer,
                    credentialIssuer = issuerMetadata?.credentialIssuer ?: authorizationServer,
                    preferredClientStatusPeriod = issuerMetadata?.preferredClientStatusPeriod,
                )
            ).getOrThrow()

            val cnfKey = wia.payload.confirmationClaim?.jsonWebKey
            require(cnfKey != null) { "Instance attestation has no cnf.jwk — PoP key cannot be verified" }
            require(cnfKey.jwkThumbprint == keyMaterial.jsonWebKey.jwkThumbprint) {
                "keyMaterial does not match the cnf key in the instance attestation. " +
                        "The PoP JWT will not verify on the server. " +
                        "Expected cnf thumbprint: ${cnfKey.jwkThumbprint}, " +
                        "got keyMaterial thumbprint: ${keyMaterial.jsonWebKey.jwkThumbprint}"
            }

            val pop = catching {
                BuildClientAttestationPoPJwt.invoke(
                    signJwt = SignJwt(keyMaterial, JwsHeaderNone()),
                    clientId = oAuth2Client.clientId,
                    audience = authorizationServer,
                    nonce = null // TODO: Read challenge like for DPoP
                )
            }.getOrThrow()
            wia.jws to pop.jws
        } else null to null

        val dpopHeader = useDpop.takeIf { it }?.let {
            BuildDPoPHeader(
                signDpop = signDpop,
                url = resourceUrl,
                httpMethod = httpMethod.value,
                nonce = currentDpopNonce(resourceUrl),
                randomSource = randomSource,
            )
        }

        return {
            headers {
                clientAttJwt?.let { append(HttpHeaders.OAuthClientAttestation, it.toString()) }
                clientAttPop?.let { append(HttpHeaders.OAuthClientAttestationPop, it.toString()) }
                dpopHeader?.let { append(HttpHeaders.DPoP, it.toString()) }
            }
        }
    }

    private fun OAuth2AuthorizationServerMetadata.supportsClientAuth(): Boolean =
        tokenEndPointAuthMethodsSupported?.contains(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true
}

private val HttpResponse.dpopNonce: String?
    get() = headers[HttpHeaders.DPoPNonce]

data class TokenResponseWithDpopNonce(
    val params: TokenResponseParameters,
    val dpopNonce: String?,
)

private suspend fun parseTokenIntrospectionResponse(
    body: String,
    verifyTokenIntrospectionJwt: suspend (JwsCompactTyped<TokenIntrospectionResponse>) -> Boolean,
    requestedResponseFormat: TokenIntrospectionRequest.ResponseFormat?,
): TokenIntrospectionResponse = catchingUnwrapped {
    if (requestedResponseFormat == TokenIntrospectionRequest.ResponseFormat.JWT) {
        parseJwt(body, verifyTokenIntrospectionJwt)
    } else {
        catchingUnwrapped {
            joseCompliantSerializer.decodeFromString(TokenIntrospectionResponse.serializer(), body)
        }.getOrElse {
            parseJwt(body, verifyTokenIntrospectionJwt)
        }
    }
}.getOrElse {
    throw InvalidToken("Token introspection response could not be parsed", it)
}

private suspend fun parseJwt(
    body: String,
    verifyTokenIntrospectionJwt: suspend (JwsCompactTyped<TokenIntrospectionResponse>) -> Boolean
): TokenIntrospectionResponse =
    joseCompliantSerializer.decodeFromString(TokenIntrospectionJwtResponse.serializer(), body).let { jwtResponse ->
        JwsCompactTyped<TokenIntrospectionResponse>(jwtResponse.jwt).run {
            require(verifyTokenIntrospectionJwt(this)) { "Token introspection JWT validation failed" }
            payload
        }
    }
