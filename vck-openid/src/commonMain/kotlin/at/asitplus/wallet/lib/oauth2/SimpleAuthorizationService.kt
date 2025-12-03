package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferGrants
import at.asitplus.openid.CredentialOfferGrantsAuthCode
import at.asitplus.openid.CredentialOfferGrantsPreAuthCode
import at.asitplus.openid.CredentialOfferUrlParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.oidvci.CodeService
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.DefaultCodeService
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.oidvci.OAuth2AuthorizationServerAdapter
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFun
import at.asitplus.wallet.lib.oidvci.OAuth2LoadUserFunInput
import at.asitplus.wallet.lib.oidvci.TokenInfo
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.RequestParser
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * with the actual authentication and authorization logic for credential schemes implemented in [strategy].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 * Also implements necessary parts of
 * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
 * , Draft 03, 2025-02-07, e.g.
 * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126),
 * [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636),
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449),
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html)
 * [OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
 * [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
 */
class SimpleAuthorizationService(
    /** Used to filter authorization details and scopes. */
    private val strategy: AuthorizationServiceStrategy,
    /** Used to load the actual user data during [authorize]. */
    /** Used to create and verify authorization codes during issuing. */
    private val codeService: CodeService = DefaultCodeService(),
    /** Used in several fields in [OAuth2AuthorizationServerMetadata], to provide endpoint URLs to clients. */
    override val publicContext: String = "https://wallet.a-sit.at/authorization-server",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.authorizationEndpoint], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [authorize].
     */
    private val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.tokenEndpoint], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    private val tokenEndpointPath: String = "/token",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.pushedAuthorizationRequestEndpoint], i.e. implementers need to
     * forward POST requests to that URI (which starts with [publicContext]) to [par].
     */
    private val pushedAuthorizationRequestEndpointPath: String = "/par",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.userInfoEndpoint], i.e. implementers need to forward POST or GET
     * requests to that URI (which starts with [publicContext]) to [userInfo].
     */
    private val userInfoEndpointPath: String = "/userinfo",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.introspectionEndpoint], i.e. implementers need to forward POST or GET
     * requests to that URI (which starts with [publicContext]) to [getTokenInfo].
     */
    private val introspectionEndpointPath: String = "/introspect",
    /** Associates issuer_state with credential offers. */
    private val issuerStateToCredentialOffer: MapStore<String, CredentialOffer> = DefaultMapStore(),
    /** Associates issued codes with the auth request from the client. */
    private val codeToClientAuthRequest: MapStore<String, ClientAuthRequest> = DefaultMapStore(),
    /** Associates issued refresh tokens with the auth request from the client. *Refresh tokens are usually long-lived!* */
    private val refreshTokenToAuthRequest: MapStore<String, ClientAuthRequest> =
        DefaultMapStore(lifetime = 30.days),
    /** Associates the issued request_uri to the auth request from the client. */
    private val requestUriToPushedAuthorizationRequest: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Service to create and validate access tokens. */
    private val tokenService: TokenService = TokenService.bearer(),
    /** Handles client authentication in [par] and [token]. */
    private val clientAuthenticationService: ClientAuthenticationService = ClientAuthenticationService(
        enforceClientAuthentication = false,
        verifyClientAttestationJwt = { true }
    ),
    /** Used to parse requests from clients, e.g., when using JWT-Secured Authorization Requests (RFC 9101) */
    private val requestParser: RequestParser = RequestParser(
        /** By default, do not retrieve authn requests referenced by `request_uri`. */
        remoteResourceRetriever = { null },
        /** Trust all JWS signatures, client will be authenticated anyway. */
        requestObjectJwsVerifier = { true },
        /** Not necessary to load the authn request referenced by `request_uri`. */
        buildRequestObjectParameters = { null }
    ),
    /**
     * Sets [OAuth2AuthorizationServerMetadata.requirePushedAuthorizationRequests],
     * must be set to `true` for OID4VC HAIP
     */
    private val requirePushedAuthorizationRequests: Boolean = true,
    /**
     * Sets [OAuth2AuthorizationServerMetadata.requestObjectSigningAlgorithmsSupported].
     * Currently, we only support [JwsAlgorithm.Signature.ES256].
     * If set the client MAY wrap [RequestParameters] as [JarRequestParameters]
     * - this is the default behaviour of [at.asitplus.wallet.lib.ktor.openid.OAuth2KtorClient]
     */
    private val requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>? = setOf(JwsAlgorithm.Signature.ES256),
    /** Used for [OAuth2AuthorizationServerMetadata.clientAttestationSigningAlgValuesSupportedStrings] */
    private val supportedSigningAlgorithms: Set<JwsAlgorithm.Signature> = setOf(JwsAlgorithm.Signature.ES256)
) : OAuth2AuthorizationServerAdapter, AuthorizationService {

    private val _metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
            pushedAuthorizationRequestEndpoint = "$publicContext$pushedAuthorizationRequestEndpointPath",
            userInfoEndpoint = "$publicContext$userInfoEndpointPath",
            introspectionEndpoint = "$publicContext$introspectionEndpointPath",
            introspectionEndpointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH),
            requirePushedAuthorizationRequests = requirePushedAuthorizationRequests,
            tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH), // per OID4VC HAIP
            clientAttestationSigningAlgValuesSupportedStrings = supportedSigningAlgorithms
                .map { it.identifier }.toSet(),
            clientAttestationPopSigningAlgValuesSupportedStrings = supportedSigningAlgorithms
                .map { it.identifier }.toSet(),
            dpopSigningAlgValuesSupportedStrings = tokenService.dpopSigningAlgValuesSupportedStrings,
            requestObjectSigningAlgorithmsSupportedStrings = requestObjectSigningAlgorithms
                ?.map { it.identifier }?.toSet(),
            grantTypesSupported = setOfNotNull(
                OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE,
                OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE,
                OpenIdConstants.GRANT_TYPE_TOKEN_EXCHANGE,
                if (tokenService.supportsRefreshTokens) OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN else null,
            )
        )
    }

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.WellKnownPaths.OpenidConfiguration],
     * and under `/.well-known/oauth-authorization-server`,
     * see [OpenIdConstants.WellKnownPaths.OauthAuthorizationServer].
     */
    override suspend fun metadata(): OAuth2AuthorizationServerMetadata = _metadata

    @Deprecated("Use credentialOfferWithAuthorizationCode with parameter configurationIds")
    suspend fun credentialOfferWithAuthorizationCode(
        credentialIssuer: String,
    ) = credentialOfferWithAuthorizationCode(
        credentialIssuer = credentialIssuer,
        configurationIds = strategy.allCredentialIdentifier()
    )

    /**
     * Offer some credential identifiers from [strategy] to clients with auth-code flow.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param credentialIssuer the public context of an [CredentialIssuer]
     */
    suspend fun credentialOfferWithAuthorizationCode(
        credentialIssuer: String,
        configurationIds: Collection<String> = this.strategy.allCredentialIdentifier(),
    ): CredentialOffer = codeService.provideCode().let { issuerState ->
        CredentialOffer(
            credentialIssuer = credentialIssuer,
            configurationIds = configurationIds.ifEmpty { strategy.allCredentialIdentifier() }.toSet(),
            grants = CredentialOfferGrants(
                authorizationCode = CredentialOfferGrantsAuthCode(
                    issuerState = issuerState,
                    authorizationServer = publicContext
                ),
            )
        ).also {
            issuerStateToCredentialOffer.put(issuerState, it)
        }
    }

    /**
     * Offer all available schemes from [strategy] to clients.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param user used to create the credential when the wallet app requests the credential
     * @param credentialIssuer the public context of an [CredentialIssuer]
     */
    suspend fun credentialOfferWithPreAuthnForUser(
        user: OidcUserInfoExtended,
        credentialIssuer: String,
        configurationIds: Collection<String> = this.strategy.allCredentialIdentifier(),
    ): CredentialOffer = CredentialOffer(
        credentialIssuer = credentialIssuer,
        configurationIds = configurationIds.ifEmpty { strategy.allCredentialIdentifier() }.toSet(),
        grants = CredentialOfferGrants(
            preAuthorizedCode = CredentialOfferGrantsPreAuthCode(
                preAuthorizedCode = providePreAuthorizedCode(user),
                authorizationServer = publicContext
            )
        )
    )

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param input as sent from the client as `POST` body
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun par(
        input: String,
        httpRequest: RequestInfo?,
    ) = par(
        request = requestParser.parseRequestParameters(input).getOrThrow().parameters,
        httpRequest = httpRequest
    )

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client to validate authentication
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun par(
        request: RequestParameters,
        httpRequest: RequestInfo?,
    ) = catching {
        val actualRequest = request.extractPushedRequestParams()
        Napier.i("par called with $actualRequest")
        clientAuthenticationService.authenticateClient(httpRequest, actualRequest.clientId)
        actualRequest.validate()
        val requestUri = "urn:ietf:params:oauth:request_uri:${uuid4()}".also {
            requestUriToPushedAuthorizationRequest.put(it, actualRequest)
        }
        PushedAuthenticationResponseParameters(
            requestUri = requestUri,
            expires = 5.minutes,
        )
    }

    private suspend fun RequestParameters.extractPushedRequestParams() = when (this) {
        is JarRequestParameters -> {
            require(requestUri == null) { "request_uri must not be set for PAR" }
            requestParser.extractRequest(this, null)?.parameters as? AuthenticationRequestParameters
                ?: throw InvalidRequest("request must contain valid authorization request parameters")
        }

        is AuthenticationRequestParameters -> this
        else -> throw InvalidRequest("Request is neither plain nor JAR")
    }

    /**
     * Builds the authentication response for this specific user from [loadUserFun].
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL built from client's `redirect_uri` with `code` parameter, [KmmResult] may contain a [OAuth2Exception]
     */
    override suspend fun authorize(
        input: RequestParameters,
        loadUserFun: OAuth2LoadUserFun,
    ) = catching {
        val actualRequest = extractRequestForAuthorize(input).validate()
        val userInfo = loadUserFun(OAuth2LoadUserFunInput(actualRequest)).getOrElse {
            throw InvalidRequest("Could not load user info for request $input", it)
        }
        with(actualRequest) {
            issueCodeForUserInfo(userInfo, state, codeChallenge, authorizationDetails, scope, redirectUrl!!)
                .also { Napier.i("authorize returns $it") }
        }
    }

    internal suspend fun issueCodeForUserInfo(
        userInfo: OidcUserInfoExtended,
        state: String?,
        codeChallenge: String?,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
        redirectUrl: String,
    ): AuthenticationResponseResult.Redirect {
        val response = AuthenticationResponseParameters(
            code = codeService.provideCode().also { code ->
                codeToClientAuthRequest.put(
                    code,
                    ClientAuthRequest(
                        issuedCode = code,
                        userInfo = userInfo,
                        scope = scope,
                        authnDetails = authorizationDetails,
                        codeChallenge = codeChallenge
                    )
                )
            },
            state = state,
        )

        val url = URLBuilder(redirectUrl)
            .apply { response.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()

        return AuthenticationResponseResult.Redirect(url, response)
    }

    internal suspend fun extractRequestForAuthorize(
        input: RequestParameters,
    ): AuthenticationRequestParameters = when (input) {
        is AuthenticationRequestParameters -> input
        is JarRequestParameters -> input.requestUri?.let {
            requestUriToPushedAuthorizationRequest.remove(it)?.apply {
                if (clientId != input.clientId)
                    throw InvalidRequest("client_id not matching from par: ${input.clientId} vs $clientId")
            }
        } ?: (requestParser.extractRequest(input, null)?.parameters as? AuthenticationRequestParameters)
        ?: throw InvalidRequest("could not parse request object from request")

        is RequestObjectParameters -> throw InvalidRequest("could not parse request object from request")
        is SignatureRequestParameters -> throw InvalidRequest("could not parse request object from request")
    }

    /**
     * Validates basic requirements to [AuthenticationRequestParameters]:
     *  * [AuthenticationRequestParameters.redirectUrl] needs to be set
     *  * [AuthenticationRequestParameters.issuerState] needs to conform to our internal state
     *  * [AuthenticationRequestParameters.scope] is validated by [strategy]
     *  * [AuthenticationRequestParameters.authorizationDetails] are validated by [strategy]
     */
    private suspend fun AuthenticationRequestParameters.validate(): AuthenticationRequestParameters {
        require(redirectUrl != null) { "redirect_uri not set" }
        scope?.let {
            strategy.filterScope(it)
                ?: throw InvalidScope("No matching scope in $it")
        }
        authorizationDetails?.let {
            strategy.validateAuthorizationDetails(it)
        }
        if (issuerState != null) {
            // The wallet could have started an auth code flow without any credential offer,
            // so the issuerState may be in fact null.
            if (!codeService.verifyAndRemove(issuerState!!))
                throw InvalidGrant("issuer_state invalid: $issuerState")
            val credentialOffer = issuerStateToCredentialOffer.remove(issuerState!!)
                ?: throw InvalidGrant("issuer_state invalid: $issuerState")
            if (scope != null) {
                if (!strategy.validateScope(scope!!, credentialOffer.configurationIds))
                    throw InvalidScope("Scope not from credential offer: $scope")
            }
            if (authorizationDetails != null) {
                if (!strategy.validateAuthorizationDetails(authorizationDetails!!, credentialOffer.configurationIds))
                    throw InvalidAuthorizationDetails("AuthnDetails not from credential offer: $authorizationDetails")
            }
        }

        return this
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token, uses [tokenService].
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client, to validate authentication
     *
     * @return [KmmResult] may contain a [OAuth2Exception], especially a [UseDpopNonce]
     */
    override suspend fun token(
        request: TokenRequestParameters,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("token called with $request")
        clientAuthenticationService.authenticateClient(httpRequest, request.clientId)
        if (request.grantType == OpenIdConstants.GRANT_TYPE_TOKEN_EXCHANGE) {
            val userInfoEndpoint = metadata().userInfoEndpoint
                ?: throw InvalidGrant("token_exchange requires userInfoEndpoint")
            return@catching tokenService.tokenExchange(request, userInfoEndpoint, httpRequest)
        }
        val validatedClientKey = tokenService.verification.extractValidatedClientKey(httpRequest).getOrThrow()

        val clientAuthRequest = request.loadClientAuthnRequest(httpRequest, validatedClientKey)
            ?: throw InvalidGrant("could not load user info for $request")

        request.code?.let { code ->
            clientAuthRequest.codeChallenge?.let {
                validateCodeChallenge(code, request.codeVerifier, clientAuthRequest.codeChallenge)
            }
        }
        val token = if (request.authorizationDetails != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = strategy.matchAndFilterAuthorizationDetailsForTokenResponse(
                    clientAuthRequest.authnDetails,
                    request.authorizationDetails!!
                ),
                scope = null,
                validatedClientKey = validatedClientKey,
            )
        } else if (request.scope != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = request.validatedScope(clientAuthRequest),
                validatedClientKey = validatedClientKey,
            )
        } else if (clientAuthRequest.authnDetails != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = strategy.filterAuthorizationDetailsForTokenResponse(clientAuthRequest.authnDetails),
                scope = null,
                validatedClientKey = validatedClientKey,
            )
        } else if (clientAuthRequest.scope != null) {
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = strategy.filterScope(clientAuthRequest.scope)
                    ?: throw InvalidScope("No valid scope in ${clientAuthRequest.scope}"),
                validatedClientKey = validatedClientKey,
            )
        } else {
            throw InvalidRequest("neither authorization details nor scope in request")
        }
        token.refreshToken?.let {
            refreshTokenToAuthRequest.put(it, clientAuthRequest)
        }
        Napier.i("token returns $token")
        token
    }

    private fun validateCodeChallenge(code: String, codeVerifier: String?, codeChallenge: String) {
        if (codeVerifier == null) {
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
        val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
        if (codeChallenge != codeChallengeCalculated) {
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
    }

    private fun TokenRequestParameters.validatedScope(clientAuthnRequest: ClientAuthRequest): String? {
        if (clientAuthnRequest.scope == null)
            throw InvalidRequest("Scope not from auth code: ${scope}, for code ${clientAuthnRequest.issuedCode}")
        scope?.split(" ")?.forEach { singleScope ->
            if (!clientAuthnRequest.scope.contains(singleScope))
                throw InvalidRequest("Scope not from auth code: $singleScope")
        }
        return scope
    }

    internal suspend fun TokenRequestParameters.loadClientAuthnRequest(
        httpRequest: RequestInfo?,
        validatedClientKey: JsonWebKey?,
    ): ClientAuthRequest? = when (grantType) {
        OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
            if (code == null || !codeService.verifyAndRemove(code!!)) {
                throw InvalidCode("code not valid: $code")
            }
            code?.let { codeToClientAuthRequest.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
            if (preAuthorizedCode == null || !codeService.verifyAndRemove(preAuthorizedCode!!)) {
                throw InvalidGrant("pre-authorized code not valid: $preAuthorizedCode")
            }
            preAuthorizedCode?.let { codeToClientAuthRequest.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN -> {
            if (refreshToken == null) {
                throw InvalidGrant("refresh_token is null")
            }
            tokenService.verification.validateRefreshToken(refreshToken!!, httpRequest, validatedClientKey)
            refreshToken?.let { refreshTokenToAuthRequest.remove(it) }
        }

        else -> throw InvalidRequest("grant_type invalid")
    }

    suspend fun providePreAuthorizedCode(
        userInfo: OidcUserInfoExtended,
    ): String = codeService.provideCode().also {
        codeToClientAuthRequest.put(
            it,
            ClientAuthRequest(
                issuedCode = it,
                userInfo = userInfo,
                scope = strategy.validScopes(),
                authnDetails = strategy.validAuthorizationDetails(publicContext)
            )
        )
    }

    /**
     * Returns the user info associated with this access token, when the token in [authorizationHeader] is correct.
     *
     * @return [KmmResult] may contain a [OAuth2Exception], especially a [UseDpopNonce]
     */
    override suspend fun userInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject> = catching {
        tokenService.verification.validateAccessToken(authorizationHeader, httpRequest).getOrThrow()
        with(tokenService.readUserInfo(authorizationHeader, httpRequest)) {
            userInfoExtended?.jsonObject
                ?: throw InvalidGrant("no user info found for $authorizationHeader")
        }
    }

    /**
     * Obtains a JSON object representing [at.asitplus.openid.OidcUserInfo] from the Authorization Server, and
     * since we're implementing [OAuth2AuthorizationServerAdapter] here, this is the same as [userInfo].
     */
    override suspend fun getUserInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject> = catching {
        with(tokenService.readUserInfo(authorizationHeader, httpRequest)) {
            userInfoExtended?.jsonObject
                ?: throw InvalidGrant("no user info found for $authorizationHeader")
        }
    }

    /**
     * Obtains information about the token, since we're in-memory here (as an [OAuth2AuthorizationServerAdapter],
     * we can directly access our [tokenService].
     */
    override suspend fun getTokenInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenInfo> = catching {
        tokenService.verification.getTokenInfo(authorizationHeader)
    }

    override suspend fun tokenIntrospection(
        request: TokenIntrospectionRequest,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenIntrospectionResponse> = catching {
        // TODO Which client_id to pass?
        clientAuthenticationService.authenticateClient(httpRequest, null)
        val validated = runCatching {
            tokenService.verification.getTokenInfo(request.token)
        }.getOrElse {
            return@catching TokenIntrospectionResponse(active = false)
        }
        TokenIntrospectionResponse(
            active = true,
            scope = validated.scope,
            authorizationDetails = validated.authorizationDetails,
        )
    }

    override suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<Boolean> = catching {
        tokenService.verification.validateAccessToken(authorizationHeader, httpRequest).isSuccess
    }

    override suspend fun getDpopNonce() = tokenService.dpopNonce()
}
