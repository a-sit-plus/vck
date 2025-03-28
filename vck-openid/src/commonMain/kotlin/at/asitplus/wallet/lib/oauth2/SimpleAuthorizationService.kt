package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidvci.*
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidCode
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidGrant
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidScope
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.RequestParser
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Duration.Companion.minutes


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * with the actual authentication and authorization logic implemented in [strategy].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
 * Also implements necessary parts of
 * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
 * , Draft 03, 2025-02-07, e.g.
 * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126),
 * [Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636),
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449),
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html)
 */
class SimpleAuthorizationService(
    /** Used to filter authorization details and scopes. */
    private val strategy: AuthorizationServiceStrategy,
    /** Used to load the actual user data during [authorize]. */
    private val dataProvider: OAuth2DataProvider,
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
    /** Associates issuer_state with credential offers. */
    private val issuerStateToCredentialOffer: MapStore<String, CredentialOffer> = DefaultMapStore(),
    /** Associates issued codes with the auth request from the client. */
    private val codeToClientAuthRequest: MapStore<String, ClientAuthRequest> = DefaultMapStore(),
    /** Associates issued refresh token with the auth request from the client. *Refresh tokens are usually long-lived!* */
    private val refreshTokenToAuthRequest: MapStore<String, ClientAuthRequest> = DefaultMapStore(),
    /** Associates the issued request_uri to the auth request from the client. */
    private val requestUriToPushedAuthorizationRequest: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Service to create and validate access tokens. */
    private val tokenService: TokenService = TokenService.bearer(
        nonceService = DefaultNonceService(),
    ),
    /** Handles client authentication in [par] and [token]. */
    private val clientAuthenticationService: ClientAuthenticationService = ClientAuthenticationService(
        enforceClientAuthentication = false,
        verifierJwsService = DefaultVerifierJwsService(),
        verifyClientAttestationJwt = { true }
    ),
    /** Used to parse requests from clients, e.g. when using JWT-Secured Authorization Requests (RFC 9101) */
    private val requestParser: RequestParser = RequestParser(
        /** By default, do not retrieve authn requests referenced by `request_uri`. */
        remoteResourceRetriever = { null },
        /** Trust all JWS signatures, client will be authenticated anyway. */
        requestObjectJwsVerifier = { true },
        /** Not necessary to load the authn request referenced by `request_uri`. */
        buildRequestObjectParameters = { null }
    ),
) : OAuth2AuthorizationServerAdapter {

    override val tokenVerificationService: TokenVerificationService
        get() = tokenService.verification


    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION],
     * and under `/.well-known/oauth-authorization-server`,
     * see [OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER]
     */
    override val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
            pushedAuthorizationRequestEndpoint = "$publicContext$pushedAuthorizationRequestEndpointPath",
            requirePushedAuthorizationRequests = true, // per OID4VC HAIP
            tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH), // per OID4VC HAIP
            dpopSigningAlgValuesSupportedStrings = tokenService.dpopSigningAlgValuesSupportedStrings
        )
    }

    /**
     * Offer all available schemes from [strategy] to clients.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param credentialIssuer the public context of an [CredentialIssuer]
     */
    suspend fun credentialOfferWithAuthorizationCode(
        credentialIssuer: String,
    ): CredentialOffer = CredentialOffer(
        credentialIssuer = credentialIssuer,
        configurationIds = strategy.allCredentialIdentifier(),
        grants = CredentialOfferGrants(
            authorizationCode = CredentialOfferGrantsAuthCode(
                issuerState = codeService.provideCode(),
                authorizationServer = publicContext
            ),
        )
    ).also {
        issuerStateToCredentialOffer.put(it.grants!!.authorizationCode!!.issuerState!!, it)
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
    ): CredentialOffer = CredentialOffer(
        credentialIssuer = credentialIssuer,
        configurationIds = strategy.allCredentialIdentifier(),
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
     * @param input as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     */
    suspend fun par(
        input: String,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ) = catching {
        requestParser.parseRequestParameters(input).getOrThrow()
            .let { it.parameters as? AuthenticationRequestParameters }
            ?.let { par(it, clientAttestation, clientAttestationPop) }
            ?: throw InvalidRequest("Could not parse request parameters from $input")
                .also { Napier.w("par: could not parse request parameters from $input") }
    }

    /**
     * Pushed authorization request endpoint as defined in [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     * Clients send their authorization request as HTTP `POST` with `application/x-www-form-urlencoded` to the AS.
     *
     * Responses have to be sent with HTTP status code `201`.
     *
     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     */
    suspend fun par(
        request: AuthenticationRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
    ) = catching {
        Napier.i("pushedAuthorization called with $request")

        if (request.requestUri != null) {
            Napier.w("par: client set request_uri: ${request.requestUri}")
            throw InvalidRequest("request_uri must not be set")
        }

        clientAuthenticationService.authenticateClient(clientAttestation, clientAttestationPop, request.clientId)
        val actualRequest = requestParser.extractActualRequest(request).getOrThrow()
        validateAuthnRequest(actualRequest)

        val requestUri = "urn:ietf:params:oauth:request_uri:${uuid4()}".also {
            requestUriToPushedAuthorizationRequest.put(it, actualRequest)
        }
        PushedAuthenticationResponseParameters(
            requestUri = requestUri,
            expires = 5.minutes,
        )
    }

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    suspend fun authorize(input: String) = catching {
        requestParser.parseRequestParameters(input).getOrThrow()
            .let { it.parameters as? AuthenticationRequestParameters }
            ?.let { authorize(it) }
            ?: throw InvalidRequest("Could not parse request parameters from $input")
                .also { Napier.w("authorize: could not parse request parameters from $input") }
    }

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    suspend fun authorize(input: AuthenticationRequestParameters) = catching {
        Napier.i("authorize called with $input")

        val request = if (input.requestUri != null) {
            val par = requestUriToPushedAuthorizationRequest.remove(input.requestUri!!)
                ?: throw InvalidRequest("request_uri set, but not found")
                    .also { Napier.w("authorize: client sent invalid request_uri: ${input.requestUri}") }
            if (par.clientId != input.clientId) {
                throw InvalidRequest("client_id not matching from par")
                    .also { Napier.w("authorize: invalid client_id: ${input.clientId} vs par ${par.clientId}") }
            }
            par
        } else {
            requestParser.extractActualRequest(input).getOrThrow()
        }
        validateAuthnRequest(request)

        val code = codeService.provideCode().also { code ->
            val userInfo = dataProvider.loadUserInfo(request, code)
                ?: throw InvalidRequest("Could not load user info for request $request")
                    .also { Napier.w("authorize: could not load user info from $request") }
            codeToClientAuthRequest.put(
                code,
                ClientAuthRequest(
                    issuedCode = code,
                    userInfo = userInfo,
                    scope = request.scope,
                    authnDetails = request.authorizationDetails,
                    codeChallenge = request.codeChallenge
                )
            )
        }
        val response = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )

        val url = URLBuilder(request.redirectUrl!!)
            .apply { response.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()

        AuthenticationResponseResult.Redirect(url, response)
            .also { Napier.i("authorize returns $it") }
    }

    private suspend fun validateAuthnRequest(request: AuthenticationRequestParameters) {
        if (request.redirectUrl == null)
            throw InvalidRequest("redirect_uri not set")
                .also { Napier.w("authorize: client did not set redirect_uri in $request") }

        if (request.scope != null) {
            strategy.filterScope(request.scope!!)
                ?: throw InvalidScope("No matching scope in ${request.scope}")
                    .also { Napier.w("authorize: scope ${request.scope} does not contain a valid credential id") }
        }

        if (request.issuerState != null) {
            if (!codeService.verifyAndRemove(request.issuerState!!)
                || issuerStateToCredentialOffer.remove(request.issuerState!!) == null
            ) {
                throw InvalidGrant("issuer_state invalid: ${request.issuerState}")
                    .also { Napier.w("authorize: issuer_state invalid: ${request.issuerState}") }
            }
            // the actual credential offer is irrelevant, because we're always offering all credentials
        }

        if (request.authorizationDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(request.authorizationDetails!!)
            if (filtered.isEmpty()) {
                throw InvalidRequest("No matching authorization details")
                Napier.w("authorize: authorization details not valid: ${request.authorizationDetails}")
            }
        }
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param httpRequest information about the HTTP request from the client, to validate authentication
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(
        request: TokenRequestParameters,
        httpRequest: RequestInfo? = null,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("token called with $request")

        val clientAuthRequest = request.loadClientAuthRequest(httpRequest)
            ?: throw InvalidGrant("could not load user info for $request")
                .also { Napier.w("token: could not load user info for $request}") }

        request.code?.let { code ->
            clientAuthRequest.codeChallenge?.let {
                validateCodeChallenge(code, request.codeVerifier, clientAuthRequest.codeChallenge)
            }
        }

        clientAuthenticationService.authenticateClient(
            httpRequest?.clientAttestation,
            httpRequest?.clientAttestationPop,
            request.clientId
        )
        val token = if (request.authorizationDetails != null) {
            if (clientAuthRequest.authnDetails == null)
                throw InvalidRequest("No authn details for issued code: ${clientAuthRequest.issuedCode}")

            val filtered = strategy.filterAuthorizationDetails(request.authorizationDetails!!).also {
                if (it.isEmpty())
                    throw InvalidRequest("No valid authorization details in ${request.authorizationDetails}")
                it.forEach { filter ->
                    if (!filter.requestedFromCode(clientAuthRequest))
                        throw InvalidRequest("Authorization details not from auth code: $filter")
                }
            }
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = filtered,
                scope = null
            )
        } else if (request.scope != null) {
            if (clientAuthRequest.scope == null)
                throw InvalidRequest("Scope not from auth code: ${request.scope}, for code ${clientAuthRequest.issuedCode}")
            request.scope!!.split(" ").forEach { singleScope ->
                if (!clientAuthRequest.scope.contains(singleScope))
                    throw InvalidRequest("Scope not from auth code: $singleScope")
            }
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = request.scope
            )
        } else if (clientAuthRequest.authnDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(
                clientAuthRequest.authnDetails.filterIsInstance<OpenIdAuthorizationDetails>()
            ).also {
                if (it.isEmpty())
                    throw InvalidRequest("No valid authorization details in ${clientAuthRequest.authnDetails}")
            }
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = filtered,
                scope = null
            )
        } else if (clientAuthRequest.scope != null) {
            val scope = strategy.filterScope(clientAuthRequest.scope)
                ?: throw InvalidScope("No valid scope in ${clientAuthRequest.scope}")
            tokenService.generation.buildToken(
                httpRequest = httpRequest,
                userInfo = clientAuthRequest.userInfo,
                authorizationDetails = null,
                scope = scope
            )
        } else {
            Napier.w("token: request can not be parsed: $request")
            throw InvalidRequest("neither authorization details nor scope in request")
        }
        token.refreshToken?.let {
            refreshTokenToAuthRequest.put(it, clientAuthRequest)
        }
        Napier.i("token returns $token")
        token
    }

    private fun OpenIdAuthorizationDetails.requestedFromCode(clientAuthRequest: ClientAuthRequest): Boolean =
        clientAuthRequest.authnDetails!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    private fun validateCodeChallenge(code: String, codeVerifier: String?, codeChallenge: String) {
        if (codeVerifier == null) {
            Napier.w("token: client did not provide any code verifier: $codeVerifier for $code")
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
        val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
        if (codeChallenge != codeChallengeCalculated) {
            Napier.w("token: client did not provide correct code verifier: $codeVerifier for $code")
            throw InvalidGrant("code verifier invalid: $codeVerifier for $code")
        }
    }

    private suspend fun TokenRequestParameters.loadClientAuthRequest(
        httpRequest: RequestInfo? = null,
    ): ClientAuthRequest? = when (grantType) {
        OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
            if (code == null || !codeService.verifyAndRemove(code!!))
                throw InvalidCode("code not valid: $code")
                    .also { Napier.w("token: client did not provide correct code: $code") }
            code?.let { codeToClientAuthRequest.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
            if (preAuthorizedCode == null || !codeService.verifyAndRemove(preAuthorizedCode!!))
                throw InvalidGrant("pre-authorized code not valid: $preAuthorizedCode")
                    .also { Napier.w("token: pre-authorized code not valid: $preAuthorizedCode") }
            preAuthorizedCode?.let { codeToClientAuthRequest.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN -> {
            if (refreshToken == null)
                throw InvalidGrant("refresh_token is null")
                    .also { Napier.w("token: refresh_token is null") }
            tokenService.verification.validateRefreshToken(refreshToken!!, httpRequest)
            refreshToken?.let { refreshTokenToAuthRequest.remove(it) }
        }

        else -> throw InvalidRequest("grant_type invalid")
            .also { Napier.w("token: client did not provide valid grant_type: $grantType") }
    }

    suspend fun providePreAuthorizedCode(user: OidcUserInfoExtended): String =
        codeService.provideCode().also {
            codeToClientAuthRequest.put(
                it,
                ClientAuthRequest(
                    issuedCode = it,
                    userInfo = user,
                    scope = strategy.validScopes(),
                    authnDetails = strategy.validAuthorizationDetails()
                )
            )
        }

}

