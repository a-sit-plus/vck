package at.asitplus.wallet.lib.oauth2

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.FormParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.OpenIdConstants.WellKnownPaths
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenIntrospectionJwtPayload
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.decodeFromQuery
import at.asitplus.openid.encodeToParameters
import at.asitplus.openid.formUrlEncode
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.MediaTypes.Application.TOKEN_INTROSPECTION_JWT
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client.AuthorizationForToken
import at.asitplus.wallet.lib.oauth2.OAuth2Utils.insertWellKnownPath
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationPoPJwt
import at.asitplus.wallet.lib.oidvci.BuildDPoPHeader
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration

/**
 * Implements the client side of OAuth 2.0, without sending any HTTP request itself: every call returns an
 * [HttpExchange], whose requests the caller sends with any HTTP stack. The KDoc of each method lists the
 * [ProtocolRequest]s its exchange sends; brackets mark optional requests, and `{1,3}` means the first attempt plus up
 * to two retries.
 *
 * Supported features:
 *  * Token requests and responses
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 *  * [JSON Web Token (JWT) Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)
 *  * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 *
 * DPoP nonces and attestation challenges are tracked per origin in this instance, and shared by all its exchanges.
 * DPoP nonces from the authorization server and from resource servers are kept apart, even when both share an origin.
 */
@OptIn(ExperimentalAtomicApi::class)
class OAuth2ProtocolClient @JvmOverloads constructor(
    /**
     * Implements OAuth2 protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works
     */
    val oAuth2Client: OAuth2Client,
    /**
     * Authenticates the client with an instance attestation, when the authorization server supports
     * attestation-based client authentication; `null` for no client attestation.
     */
    val clientAttestation: ClientAttestation? = null,
    /**
     * The key material the access tokens and refresh tokens get bound to, used for calculating DPoP proofs.
     * Defaults to the key of [clientAttestation], as DPoP needs the same key as the instance attestation
     * ([EUDI TS3 Wallet Unit Attestation](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)),
     * which also keeps refresh tokens usable with that persistent key; without client attestation, to an ephemeral key.
     */
    private val dpopKeyMaterial: KeyMaterial = clientAttestation?.keyMaterial ?: EphemeralKeyWithoutCert(),
    /** Source for random bytes, i.e., nonces for proof-of-possession of key material for sender-constrained tokens. */
    private val randomSource: RandomSource = RandomSource.Secure,
    /**
     * Verifies the signature of JWT responses of token introspection
     * ([RFC 9701](https://www.rfc-editor.org/rfc/rfc9701)) against the keys of the authorization server, e.g. with
     * [at.asitplus.wallet.lib.jws.VerifyJwsObjectTrusted]. When set, [callTokenIntrospection] requests JWT responses
     * and accepts nothing else; when `null`, it requests plain JSON responses
     * ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)).
     */
    private val verifyTokenIntrospectionJwt: VerifyJwsObjectFun? = null,
) {

    /** Used in [ClientAttestation.loadInstanceAttestation] to provide information about the authorization server. */
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

    /**
     * Open the [url] in a browser (so the user can authenticate at the AS), and store [state] to use in next call.
     */
    data class OpenUrlForAuthnRequest(
        val url: String,
        val state: String,
    )

    /** Store the latest attestation challenge per origin (if the AS supports challenges) */
    private val attestationChallengeByOrigin = AtomicReference(mapOf<String, String>())

    /**
     * Consumes the challenge that the AS provided in a previous response, see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     * 6.2. A challenge is single-use, so reusing it would get the next request rejected with
     * `use_attestation_challenge`.
     */
    private fun takeAttestationChallenge(url: String): String? {
        val origin = url.origin()
        var challenge: String? = null
        attestationChallengeByOrigin.update {
            challenge = it[origin]
            it - origin
        }
        return challenge
    }

    private fun hasAttestationChallenge(url: String): Boolean =
        attestationChallengeByOrigin.load().containsKey(url.origin())

    private fun updateAttestationChallenge(url: String, challenge: String?) =
        challenge?.takeIf { it.isNotBlank() }?.let {
            attestationChallengeByOrigin.update { it + (url.origin() to challenge) }
            challenge
        }

    /**
     * Stores the latest DPoP nonce per origin that the authorization server provided, for requests with client
     * authentication, see [RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid).
     */
    private val authorizationServerDpopNonces = AtomicReference(mapOf<String, String>())

    /**
     * Stores the latest DPoP nonce per origin that a resource server (e.g. the credential issuer) provided, for requests
     * with an access token, see [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9): nonces of an
     * authorization server and a resource server "are different and should not be confused with one another", even
     * when both share an origin.
     */
    private val resourceServerDpopNonces = AtomicReference(mapOf<String, String>())

    private fun String.origin(): String = Url(this).let { parsed ->
        "${parsed.protocol.name}://${parsed.host}:${parsed.port}"
    }

    private fun AtomicReference<Map<String, String>>.current(url: String): String? = load()[url.origin()]

    private fun AtomicReference<Map<String, String>>.updateNonce(url: String, nonce: String?) {
        nonce?.takeIf { it.isNotBlank() }?.let { nonce -> update { it + (url.origin() to nonce) } }
    }

    /** Stores the DPoP nonce and the attestation challenge from any response of the authorization server to [url]. */
    internal fun recordAuthorizationServerResponse(url: String, headers: Headers) {
        authorizationServerDpopNonces.updateNonce(url, headers[HttpHeaders.DPoPNonce])
        updateAttestationChallenge(url, headers[HttpHeaders.OAuthClientAttestationChallenge])
    }

    /** Stores the DPoP nonce from any response of a resource server, e.g. the credential issuer, to [url]. */
    internal fun recordResourceServerResponse(url: String, headers: Headers) {
        resourceServerDpopNonces.updateNonce(url, headers[HttpHeaders.DPoPNonce])
    }

    /**
     * Loads [OAuth2AuthorizationServerMetadata] from [authorizationServer].
     *
     * Sends `AuthorizationServerMetadata` (from [WellKnownPaths.OauthAuthorizationServer]), and only if that fails,
     * `AuthorizationServerMetadata(openidConfiguration = true)` (from [WellKnownPaths.OpenidConfiguration]).
     */
    fun loadAuthorizationServerMetadata(
        authorizationServer: String,
    ): HttpExchange<OAuth2AuthorizationServerMetadata> = PlainExchange(
        candidates = listOf(
            ProtocolRequest.AuthorizationServerMetadata(
                http = get(insertWellKnownPath(authorizationServer, WellKnownPaths.OauthAuthorizationServer)),
                openidConfiguration = false,
            ),
            ProtocolRequest.AuthorizationServerMetadata(
                http = get(insertWellKnownPath(authorizationServer, WellKnownPaths.OpenidConfiguration)),
                openidConfiguration = true,
            ),
        ),
        parse = { joseCompliantSerializer.decodeFromString<OAuth2AuthorizationServerMetadata>(it.body) },
    )

    /**
     * Uses a pre-authorized code from the authorization server to request an access token.
     *
     * Sends `([AttestationChallenge] Token){1,3}`.
     */
    @JvmOverloads
    fun requestTokenWithPreAuthorizedCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        preAuthorizedCode: String,
        transactionCode: String?,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<TokenResponseWithDpopNonce> = tokenRequest(
        oauthMetadata = oauthMetadata,
        popAudience = authorizationServer,
        issuerMetadata = issuerMetadata,
    ) {
        Napier.i("requestTokenWithPreAuthorizedCode")
        val hasScope = scope != null
        oAuth2Client.createTokenRequestParameters(
            state = uuid4().toString(),
            authorization = AuthorizationForToken.PreAuthCode(preAuthorizedCode, transactionCode),
            scope = scope,
            authorizationDetails = if (!hasScope) authorizationDetails else null
        )
    }

    /**
     * Uses the auth code to request an access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Sends `([AttestationChallenge] Token){1,3}`.
     *
     * @param url the URL as it has been redirected back from the authorization server, i.e. containing param `code`
     */
    @JvmOverloads
    fun requestTokenWithAuthCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        url: String,
        authorizationServer: String,
        state: String,
        scope: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<TokenResponseWithDpopNonce> = tokenRequest(
        oauthMetadata = oauthMetadata,
        popAudience = authorizationServer,
        issuerMetadata = issuerMetadata,
    ) {
        Napier.i("requestTokenWithAuthCode")
        Napier.d("requestTokenWithAuthCode: $url")
        val authnResponse = Url(url).decodeFromQuery<AuthenticationResponseParameters>()
        val code = authnResponse.code
            ?: throw Exception("No authn code in $url")
        val hasScope = scope != null
        oAuth2Client.createTokenRequestParameters(
            authorization = AuthorizationForToken.Code(code),
            state = state,
            scope = scope,
            authorizationDetails = if (!hasScope) authorizationDetails else null
        )
    }

    /**
     * Uses the refresh token to request a new access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Sends `([AttestationChallenge] Token){1,3}`.
     */
    @JvmOverloads
    fun requestTokenWithRefreshToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        credentialIssuer: String,
        refreshToken: String,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<TokenResponseWithDpopNonce> = tokenRequest(
        oauthMetadata = oauthMetadata,
        popAudience = oauthMetadata.issuer,
        issuerMetadata = issuerMetadata,
    ) {
        Napier.i("refreshCredential")
        Napier.d("refreshCredential: $refreshToken")
        val hasScope = scope != null
        oAuth2Client.createTokenRequestParameters(
            authorization = AuthorizationForToken.RefreshToken(refreshToken),
            state = null,
            scope = scope,
            authorizationDetails = if (!hasScope) authorizationDetails else null
        )
    }

    /**
     * Uses an access token from another client to request a new access token,
     * see [RFC8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).
     *
     * Sends `([AttestationChallenge] Token){1,3}`.
     */
    @JvmOverloads
    fun requestTokenWithTokenExchange(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        subjectToken: String,
        resource: String?,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<TokenResponseWithDpopNonce> = tokenRequest(
        oauthMetadata = oauthMetadata,
        popAudience = authorizationServer,
        issuerMetadata = issuerMetadata,
    ) {
        Napier.i("requestTokenWithTokenExchange")
        Napier.d("requestTokenWithTokenExchange: $subjectToken")
        oAuth2Client.createTokenRequestParameters(
            authorization = AuthorizationForToken.TokenExchange(subjectToken),
            state = null,
            scope = "${OpenIdConstants.SCOPE_OPENID} ${OpenIdConstants.SCOPE_PROFILE}",
            authorizationDetails = null,
            resource = resource,
        )
    }

    /** Builds the token request once with [createRequest], and posts it with client authentication. */
    private fun tokenRequest(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        popAudience: String,
        issuerMetadata: IssuerMetadata?,
        createRequest: suspend () -> TokenRequestParameters,
    ): HttpExchange<TokenResponseWithDpopNonce> = LazyExchange {
        val url = oauthMetadata.tokenEndpoint
            ?: throw IllegalArgumentException("No tokenEndpoint in $oauthMetadata")
        val request = createRequest()
        Napier.i("postToken: $url with $request")
        AuthenticatedExchange(
            client = this,
            authentication = Authentication.Client(oauthMetadata, popAudience, issuerMetadata),
            maxRetries = MAX_RETRIES_CLIENT_AUTHENTICATION,
            kind = ProtocolRequest::Token,
            request = formPost(url, request.encodeToParameters()),
            parse = { response ->
                TokenResponseWithDpopNonce(
                    joseCompliantSerializer.decodeFromString<TokenResponseParameters>(response.body),
                    response.headers[HttpHeaders.DPoPNonce],
                    response.headers[HttpHeaders.OAuthClientAttestationChallenge]
                ).also {
                    Napier.i("Received token response")
                    Napier.d("Received token response $it")
                }
            },
        )
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
     * Sends no request without PAR, and `([AttestationChallenge] PushedAuthorization){1,3}` with PAR.
     *
     * Clients need to continue the process (after getting back from the browser) with [requestTokenWithAuthCode].
     */
    @JvmOverloads
    fun startAuthorization(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        state: String = uuid4().toString(),
        issuerState: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
        scope: String? = null,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<OpenUrlForAuthnRequest> = LazyExchange {
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

        if (usePar) {
            val url = parEndpointUrl
                ?: throw Exception("No pushedAuthorizationRequestEndpoint in $oauthMetadata")
            AuthenticatedExchange(
                client = this,
                authentication = Authentication.Client(oauthMetadata, authorizationServer, issuerMetadata),
                maxRetries = MAX_RETRIES_CLIENT_AUTHENTICATION,
                kind = ProtocolRequest::PushedAuthorization,
                request = formPost(
                    url = url,
                    parameters = authRequest.encodeToParameters() +
                            (OpenIdConstants.PARAMETER_PROMPT to OpenIdConstants.PARAMETER_PROMPT_LOGIN)
                ),
                parse = { response ->
                    val parameters = JarRequestParameters(
                        clientId = oAuth2Client.clientId,
                        requestUri = joseCompliantSerializer
                            .decodeFromString<PushedAuthenticationResponseParameters>(response.body).requestUri
                            ?: throw Exception("No request_uri from PAR response at $url"),
                    ).encodeToParameters()
                    authorizationUrl(authorizationEndpointUrl, parameters, state)
                },
            )
        } else {
            ValueExchange(
                authorizationUrl(
                    authorizationEndpointUrl = authorizationEndpointUrl,
                    parameters = authRequest.encodeToParameters() +
                            (OpenIdConstants.PARAMETER_PROMPT to OpenIdConstants.PARAMETER_PROMPT_LOGIN),
                    state = state,
                )
            )
        }
    }

    private fun authorizationUrl(
        authorizationEndpointUrl: String,
        parameters: FormParameters,
        state: String,
    ): OpenUrlForAuthnRequest = URLBuilder(authorizationEndpointUrl).also { builder ->
        parameters.forEach { builder.parameters.append(it.key, it.value) }
    }.build().toString().let {
        Napier.i("Provisioning starts by returning URL to open: $it")
        OpenUrlForAuthnRequest(it, state)
    }

    private fun Set<JwsAlgorithm>?.supportsEs256(): Boolean =
        this?.contains(JwsAlgorithm.Signature.ES256) == true

    /**
     * Calls the token introspection endpoint ([OAuth2AuthorizationServerMetadata.introspectionEndpoint])
     * to check whether the given token is active, finishes with the response on success, otherwise fails with
     * [InvalidToken]. With [verifyTokenIntrospectionJwt], it asks for a JWT response
     * ([RFC 9701 4.](https://www.rfc-editor.org/rfc/rfc9701#section-4)), and accepts it only with `typ`
     * `token-introspection+jwt`, a verified signature, the authorization server as `iss`, and the `client_id` of
     * [oAuth2Client] in `aud` ([RFC 9701 5.](https://www.rfc-editor.org/rfc/rfc9701#section-5)).
     *
     * Sends `([AttestationChallenge] TokenIntrospection){1,3}`.
     */
    @JvmOverloads
    fun callTokenIntrospection(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        request: TokenIntrospectionRequest,
        popAudience: String,
        issuerMetadata: IssuerMetadata? = null,
    ): HttpExchange<TokenIntrospectionResponse> = LazyExchange {
        val url = oauthMetadata.introspectionEndpoint
            ?: throw InvalidToken("No introspection endpoint found in Authorization Server metadata")
        Napier.i("callTokenIntrospection: $url with $request")
        AuthenticatedExchange(
            client = this,
            authentication = Authentication.Client(oauthMetadata, popAudience, issuerMetadata),
            maxRetries = MAX_RETRIES_CLIENT_AUTHENTICATION,
            kind = ProtocolRequest::TokenIntrospection,
            request = formPost(
                url = url,
                parameters = request.encodeToParameters(),
                accept = verifyTokenIntrospectionJwt?.let { TOKEN_INTROSPECTION_JWT },
            ),
            parse = { response ->
                parseTokenIntrospectionResponse(response, oauthMetadata.issuer).also {
                    if (!it.active) {
                        throw InvalidToken("Introspected token is not active")
                    }
                }
            },
        )
    }

    /**
     * Loads the user info from [userInfoEndpoint] with the access token from [tokenResponse].
     *
     * Sends `UserInfo{1,2}`.
     */
    fun userInfoRequest(
        userInfoEndpoint: String,
        tokenResponse: TokenResponseParameters,
    ): HttpExchange<JsonObject> = accessTokenRequest(
        request = get(userInfoEndpoint),
        tokenResponse = tokenResponse,
        kind = ProtocolRequest::UserInfo,
        parse = { joseCompliantSerializer.decodeFromString<JsonObject>(it.body) },
    )

    /** Sends [request] with the access token from [tokenResponse], retrying once if the server asks for a DPoP nonce. */
    internal fun <T> accessTokenRequest(
        request: PreparedHttpRequest,
        tokenResponse: TokenResponseParameters,
        kind: (PreparedHttpRequest, Int) -> ProtocolRequest,
        parse: suspend (ReceivedHttpResponse) -> T,
    ): HttpExchange<T> = AuthenticatedExchange(
        client = this,
        authentication = Authentication.AccessToken(tokenResponse),
        maxRetries = MAX_RETRIES_ACCESS_TOKEN,
        kind = kind,
        request = request,
        parse = parse,
    )

    /**
     * Headers to access [resourceUrl] with the access token from [tokenResponse], i.e. [HttpHeaders.Authorization]
     * and, for DPoP-bound tokens, [HttpHeaders.DPoP]. Uses [dpopNonce], or the latest DPoP nonce that the resource
     * server at that origin provided.
     */
    @JvmOverloads
    suspend fun accessTokenHeaders(
        tokenResponse: TokenResponseParameters,
        resourceUrl: String,
        httpMethod: HttpMethod,
        dpopNonce: String? = null,
    ): Headers {
        val dpopHeader = if (tokenResponse.tokenType.equals(TOKEN_TYPE_DPOP, true)) {
            BuildDPoPHeader(
                signDpop = SignJwt(dpopKeyMaterial, JwsHeaderJwk()),
                url = resourceUrl,
                httpMethod = httpMethod.value,
                accessToken = tokenResponse.accessToken,
                nonce = dpopNonce ?: resourceServerDpopNonces.current(resourceUrl),
                randomSource = randomSource
            )
        } else null
        return Headers.build {
            append(HttpHeaders.Authorization, tokenResponse.toHttpHeaderValue())
            dpopHeader?.let { append(HttpHeaders.DPoP, it.toString()) }
        }
    }

    /**
     * Loads the instance attestation when [clientAttestation] is set and the authorization server supports
     * attestation-based client authentication, and checks that it attests [ClientAttestation.keyMaterial].
     * Called before any request of an attempt is sent, so that a request that cannot authenticate is never sent.
     */
    internal suspend fun loadInstanceAttestation(
        authentication: Authentication.Client,
    ): JwsCompactTyped<JsonWebToken>? {
        val clientAttestation = clientAttestation ?: return null
        val oauthMetadata = authentication.oauthMetadata
        if (!oauthMetadata.supportsClientAuth()) return null
        if (oauthMetadata.clientAttestationModes().combined) {
            require(oauthMetadata.supportsDPoP()) {
                "Authorization server does not support DPoP, but client attestation PoP is combined"
            }
            require(clientAttestation.keyMaterial.publicKey == dpopKeyMaterial.publicKey) {
                "Key material for DPoP and client attestation PoP are not the same"
            }
        }
        return clientAttestation.loadInstanceAttestation(
            LoadInstanceAttestationInput(
                authorizationServer = authentication.authorizationServer,
                credentialIssuer = authentication.issuerMetadata?.credentialIssuer
                    ?: authentication.authorizationServer,
                preferredClientStatusPeriod = authentication.issuerMetadata?.preferredClientStatusPeriod,
            )
        ).getOrThrow().apply {
            payload.confirmationClaim?.jsonWebKey.let { cnfKey ->
                val cryptoPublicKey = cnfKey?.toCryptoPublicKey()?.getOrNull()
                require(cryptoPublicKey != null) {
                    "Instance attestation has no cnf.jwk — PoP key cannot be verified"
                }
                require(cryptoPublicKey == clientAttestation.keyMaterial.publicKey) {
                    "keyMaterial does not match the cnf key in the instance attestation"
                }
            }
        }
    }

    /**
     * The request to fetch an attestation challenge before the next attempt to [resourceUrl], or `null` if none is
     * needed: the authorization server advertises a challenge endpoint, no challenge is cached for that origin, and
     * either a client attestation PoP is sent (normal mode), or the DPoP proof serves as that PoP (combined mode)
     * and no DPoP nonce is cached for that origin either.
     */
    internal fun attestationChallengeRequest(
        authentication: Authentication.Client,
        resourceUrl: String,
        instanceAttestation: JwsCompactTyped<JsonWebToken>?,
    ): PreparedHttpRequest? {
        val oauthMetadata = authentication.oauthMetadata
        val challengeEndpoint = oauthMetadata.challengeEndpoint ?: return null
        if (hasAttestationChallenge(resourceUrl)) return null
        val modes = oauthMetadata.clientAttestationModes()
        val needsChallenge = (instanceAttestation != null && modes.normal) ||
                (modes.combined && oauthMetadata.supportsDPoP() && authorizationServerDpopNonces.current(resourceUrl) == null)
        return if (needsChallenge) PreparedHttpRequest(challengeEndpoint, HttpMethod.Post) else null
    }

    /**
     * Headers when accessing a token endpoint (or equivalent, like PAR):
     * - the instance attestation, if [instanceAttestation] is set
     * - a client attestation PoP for that (normal mode)
     * - a DPoP proof when the authorization server advertises support for it, which also serves as the client
     *   attestation PoP in combined mode
     *
     * Uses the attestation challenge cached for the origin of [resourceUrl], or [fetchedChallenge].
     */
    internal suspend fun clientAuthenticationHeaders(
        authentication: Authentication.Client,
        resourceUrl: String,
        httpMethod: HttpMethod,
        instanceAttestation: JwsCompactTyped<JsonWebToken>?,
        fetchedChallenge: String?,
    ): Headers {
        val oauthMetadata = authentication.oauthMetadata
        val modes = oauthMetadata.clientAttestationModes()

        val attestationKey = clientAttestation?.keyMaterial
        val clientAttPop = if (instanceAttestation != null && attestationKey != null && modes.normal) {
            BuildClientAttestationPoPJwt(
                signJwt = SignJwt(attestationKey, JwsHeaderNone()),
                audience = authentication.authorizationServer,
                // nonce support must not be implemented by the AS, so we keep it optional
                nonce = takeAttestationChallenge(resourceUrl) ?: fetchedChallenge,
            )
        } else null

        val dpopHeader = if (oauthMetadata.supportsDPoP()) {
            BuildDPoPHeader(
                signDpop = SignJwt(dpopKeyMaterial, JwsHeaderJwk()),
                url = resourceUrl,
                httpMethod = httpMethod.value,
                nonce = if (modes.combined) {
                    takeAttestationChallenge(resourceUrl)
                        ?: authorizationServerDpopNonces.current(resourceUrl)
                        ?: fetchedChallenge
                } else {
                    authorizationServerDpopNonces.current(resourceUrl)
                },
                randomSource = randomSource,
            )
        } else null

        return Headers.build {
            instanceAttestation?.let { append(HttpHeaders.OAuthClientAttestation, it.jws.toString()) }
            clientAttPop?.let { append(HttpHeaders.OAuthClientAttestationPop, it.jws.toString()) }
            dpopHeader?.let { append(HttpHeaders.DPoP, it.toString()) }
        }
    }

    private data class ClientAttestationModes(val normal: Boolean, val combined: Boolean)

    private fun OAuth2AuthorizationServerMetadata.clientAttestationModes(): ClientAttestationModes {
        val methods = tokenEndPointAuthMethodsSupported.orEmpty()
            .mapNotNull { ClientAttestationPopMethod.matchByClientAuthMethod(it) }
        val normalMode = methods.contains(ClientAttestationPopMethod.AttestationPopJwt)
        return ClientAttestationModes(
            normal = normalMode,
            combined = !normalMode && methods.contains(ClientAttestationPopMethod.DpopCombined),
        )
    }

    private fun OAuth2AuthorizationServerMetadata.supportsClientAuth(): Boolean =
        tokenEndPointAuthMethodsSupported.orEmpty()
            .any { it == AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH || it == AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP }

    private fun OAuth2AuthorizationServerMetadata.supportsDPoP(): Boolean =
        dpopSigningAlgValuesSupported?.contains(
            dpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow()
        ) == true

    private fun get(url: String) = PreparedHttpRequest(url = url, method = HttpMethod.Get)

    private fun formPost(url: String, parameters: FormParameters, accept: String? = null) = PreparedHttpRequest(
        url = url,
        method = HttpMethod.Post,
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.FormUrlEncoded.toString())
            accept?.let { append(HttpHeaders.Accept, it) }
        },
        body = parameters.formUrlEncode(),
    )

    /** Parses the JWT response with [verifyTokenIntrospectionJwt], issued by [issuer], else the JSON response. */
    private suspend fun parseTokenIntrospectionResponse(
        response: ReceivedHttpResponse,
        issuer: String,
    ): TokenIntrospectionResponse = catchingUnwrapped {
        val verifyJwt = verifyTokenIntrospectionJwt
        if (verifyJwt == null) {
            joseCompliantSerializer.decodeFromString(TokenIntrospectionResponse.serializer(), response.body)
        } else {
            val contentType = response.headers[HttpHeaders.ContentType]
            require(contentType != null && ContentType.parse(contentType).match(TOKEN_INTROSPECTION_JWT)) {
                "Content-Type is not $TOKEN_INTROSPECTION_JWT: $contentType"
            }
            val jwt = JwsCompactTyped<TokenIntrospectionJwtPayload>(response.body)
            // RFC 7515 4.1.9: a typ without "/" has the prefix "application/"
            val type = jwt.jws.jwsHeader.type?.lowercase()?.removePrefix("application/")
            require(type == JwsContentTypeConstants.TOKEN_INTROSPECTION_JWT) { "Invalid typ: $type" }
            verifyJwt(jwt.jws).getOrElse { throw IllegalArgumentException("Signature not verified", it) }
            require(jwt.payload.issuer == issuer) { "iss is not the authorization server: ${jwt.payload.issuer}" }
            require(oAuth2Client.clientId in jwt.payload.audience) { "aud is not this client: ${jwt.payload.audience}" }
            jwt.payload.tokenIntrospection
        }
    }.getOrElse {
        throw InvalidToken("Token introspection response could not be parsed", it)
    }

    private companion object {
        /**
         * One retry for a DPoP nonce ([RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid))
         * and one for an attestation challenge
         * ([OA-ABCA 6.2](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#challenge-in-response)).
         */
        const val MAX_RETRIES_CLIENT_AUTHENTICATION = 2

        /** One retry for a DPoP nonce ([RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9)). */
        const val MAX_RETRIES_ACCESS_TOKEN = 1
    }
}

data class TokenResponseWithDpopNonce(
    val params: TokenResponseParameters,
    /** Value from header `DPoP-Nonce` */
    val dpopNonce: String?,
    /** Value from header `OAuth-Client-Attestation-Challenge` */
    val attestationChallenge: String?,
)
