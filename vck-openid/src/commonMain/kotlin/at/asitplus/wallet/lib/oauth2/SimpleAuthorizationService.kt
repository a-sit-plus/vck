package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.*
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock.System
import kotlin.String
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
    /** Used to load user data and filter authorization details and scopes. */
    private val strategy: AuthorizationServiceStrategy,
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
    private val codeToUserInfoStore: MapStore<String, IssuedCode> = DefaultMapStore(),
    private val accessTokenToUserInfoStore: MapStore<String, IssuedAccessToken> = DefaultMapStore(),
    private val requestUriToPushedAuthorizationRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    val tokenService: TokenService = TokenService(
        nonceService = DefaultNonceService(),
        publicContext = publicContext,
        verifierJwsService = DefaultVerifierJwsService(),
        enforceDpop = false,
        jwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert())),
        clock = System,
        timeLeeway = 5.minutes
    ),
    val clientAuthenticationService: ClientAuthenticationService = ClientAuthenticationService(
        enforceClientAuthentication = false,
        verifierJwsService = DefaultVerifierJwsService(),
        verifyClientAttestationJwt = { true }
    ),
) : OAuth2AuthorizationServerAdapter {

    override val supportsPushedAuthorizationRequests: Boolean = true


    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION]
     */
    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
            pushedAuthorizationRequestEndpoint = "$publicContext$pushedAuthorizationRequestEndpointPath",
            requirePushedAuthorizationRequests = true, // per OID4VC HAIP
            tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH), // per OID4VC HAIP
            dpopSigningAlgValuesSupportedStrings = tokenService.verifierJwsService.supportedAlgorithms.map { it.identifier }
                .toSet() // per OID4VC HAIP
        )
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
            throw OAuth2Exception(INVALID_REQUEST, "request_uri must not be set")
        }

        clientAuthenticationService.authenticateClient(clientAttestation, clientAttestationPop, request.clientId)
        validateAuthnRequest(request)

        val requestUri = "urn:ietf:params:oauth:request_uri:${uuid4()}".also {
            requestUriToPushedAuthorizationRequestStore.put(it, request)
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
    suspend fun authorize(input: AuthenticationRequestParameters) = catching {
        Napier.i("authorize called with $input")

        val request = if (input.requestUri != null) {
            val par = requestUriToPushedAuthorizationRequestStore.remove(input.requestUri!!)
                ?: throw OAuth2Exception(INVALID_REQUEST, "request_uri set, but not found")
                    .also { Napier.w("authorize: client sent invalid request_uri: ${input.requestUri}") }
            if (par.clientId != input.clientId) {
                throw OAuth2Exception(INVALID_REQUEST, "client_id not matching from par")
                    .also { Napier.w("authorize: invalid client_id: ${input.clientId} vs par ${par.clientId}") }
            }
            par
        } else {
            input
        }
        validateAuthnRequest(request)

        val code = codeService.provideCode().also { code ->
            val userInfo = strategy.loadUserInfo(request, code)
                ?: throw OAuth2Exception(INVALID_REQUEST, "Could not load user info for code=$code")
                    .also { Napier.w("authorize: could not load user info from $request") }
            codeToUserInfoStore.put(
                code,
                IssuedCode(
                    code = code,
                    userInfoExtended = userInfo,
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

    // TODO Also enable JWT-Secured Authorization Request (JAR) RFC9101
    // see also https://www.rfc-editor.org/rfc/rfc9126.html#name-the-request-request-paramet
    private fun validateAuthnRequest(request: AuthenticationRequestParameters) {
        if (request.redirectUrl == null)
            throw OAuth2Exception(INVALID_REQUEST, "redirect_uri not set")
                .also { Napier.w("authorize: client did not set redirect_uri in $request") }

        if (request.scope != null) {
            strategy.filterScope(request.scope!!)
                ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No matching scope in ${request.scope}")
                    .also { Napier.w("authorize: scope ${request.scope} does not contain a valid credential id") }
        }

        if (request.authorizationDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(request.authorizationDetails!!)
            if (filtered.isEmpty()) {
                throw OAuth2Exception(INVALID_REQUEST, "No matching authorization details")
                Napier.w("authorize: authorization details not valid: ${request.authorizationDetails}")
            }
        }
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.

     * @param request as sent from the client as `POST`
     * @param clientAttestation value of the header `OAuth-Client-Attestation`
     * @param clientAttestationPop value of the header `OAuth-Client-Attestation-PoP`
     * @param dpop value of the header `DPoP` (RFC 9449)
     * @param requestUrl public-facing URL that the client has used (to validate `DPoP`)
     * @param requestUrl HTTP method that the client has used (to validate `DPoP`)
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(
        request: TokenRequestParameters,
        clientAttestation: String? = null,
        clientAttestationPop: String? = null,
        dpop: String? = null,
        requestUrl: String? = null,
        requestMethod: HttpMethod? = null,
    ): KmmResult<TokenResponseParameters> = catching {
        Napier.i("token called with $request")

        val issuedCode: IssuedCode = request.loadIssuedCode()
            ?: throw OAuth2Exception(INVALID_REQUEST, "could not load user info for $request")
                .also { Napier.w("token: could not load user info for $request}") }

        request.code?.let { code ->
            validateCodeChallenge(code, request.codeVerifier)
        }

        // TODO Also issue refresh tokens, used to later on refresh the credential!

        clientAuthenticationService.authenticateClient(clientAttestation, clientAttestationPop, request.clientId)
        val token = tokenService.buildToken(dpop, requestUrl, requestMethod)
        val enrichedToken = if (request.authorizationDetails != null) {
            tokenForAuthnDetails(token, issuedCode, request.authorizationDetails!!)
        } else if (request.scope != null) {
            tokenForScope(token, issuedCode, request.scope!!)
        } else if (issuedCode.authnDetails != null) {
            tokenForAuthnDetails(token, issuedCode.authnDetails, issuedCode)
        } else if (issuedCode.scope != null) {
            tokenForScope(token, issuedCode.scope, issuedCode.userInfoExtended)
        } else {
            Napier.w("token: request can not be parsed: $request")
            throw OAuth2Exception(INVALID_REQUEST, "neither authorization details nor scope in request")
        }
        Napier.i("token returns $enrichedToken")
        enrichedToken
    }

    private suspend fun tokenForScope(
        token: TokenResponseParameters,
        scope: String,
        userInfo: OidcUserInfoExtended,
    ): TokenResponseParameters =
        strategy.filterScope(scope)?.let {
            token.accessToken.store(userInfo, it)
            token.copy(scope = it)
        } ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No valid scope in $scope")

    private suspend fun tokenForAuthnDetails(
        token: TokenResponseParameters,
        authnDetails: Collection<AuthorizationDetails>,
        issuedCode: IssuedCode,
    ): TokenResponseParameters {
        return strategy.filterAuthorizationDetails(
            authnDetails.filterIsInstance<OpenIdAuthorizationDetails>()
        ).let { filtered ->
            if (filtered.isEmpty())
                throw OAuth2Exception(INVALID_REQUEST, "No valid authorization details in $authnDetails")
            token.accessToken.store(issuedCode, filtered)
            token.copy(authorizationDetails = filtered)
        }
    }

    private suspend fun tokenForScope(
        token: TokenResponseParameters,
        issuedCode: IssuedCode,
        scope: String,
    ): TokenResponseParameters = strategy.filterScope(scope)?.let {
        if (issuedCode.scope == null)
            throw OAuth2Exception(INVALID_REQUEST, "Scope not from auth code: $scope, for code ${issuedCode.code}")
        it.split(" ").forEach { singleScope ->
            if (!issuedCode.scope.contains(singleScope))
                throw OAuth2Exception(INVALID_REQUEST, "Scope not from auth code: $singleScope")
        }
        token.accessToken.store(issuedCode, it)
        return token.copy(scope = it)
    } ?: throw OAuth2Exception(Errors.INVALID_SCOPE, "No valid scope in $scope")

    private suspend fun tokenForAuthnDetails(
        token: TokenResponseParameters,
        issuedCode: IssuedCode,
        authnDetails: Set<AuthorizationDetails>,
    ): TokenResponseParameters {
        if (issuedCode.authnDetails == null)
            throw OAuth2Exception(INVALID_REQUEST, "No authn details for issued code: ${issuedCode.code}")

        return strategy.filterAuthorizationDetails(authnDetails).let { filtered ->
            if (filtered.isEmpty())
                throw OAuth2Exception(INVALID_REQUEST, "No valid authorization details in $authnDetails")
            filtered.forEach { filter ->
                if (!filter.requestedFromCode(issuedCode))
                    throw OAuth2Exception(INVALID_REQUEST, "Authorization details not from auth code: $filter")
            }
            token.accessToken.store(issuedCode, filtered)
            token.copy(authorizationDetails = filtered)
        }
    }

    private fun OpenIdAuthorizationDetails.requestedFromCode(issuedCode: IssuedCode): Boolean =
        issuedCode.authnDetails!!.filterIsInstance<OpenIdAuthorizationDetails>().any { matches(it) }

    private suspend fun String.store(issuedCode: IssuedCode, filtered: Set<OpenIdAuthorizationDetails>) {
        accessTokenToUserInfoStore.put(this, IssuedAccessToken(this, issuedCode.userInfoExtended, filtered))
    }

    private suspend fun String.store(userInfo: OidcUserInfoExtended, scope: String) {
        accessTokenToUserInfoStore.put(this, IssuedAccessToken(this, userInfo, scope))
    }

    private suspend fun String.store(issuedCode: IssuedCode, scope: String) {
        accessTokenToUserInfoStore.put(this, IssuedAccessToken(this, issuedCode.userInfoExtended, scope))
    }

    private suspend fun validateCodeChallenge(code: String, codeVerifier: String?) {
        codeToUserInfoStore.get(code)?.codeChallenge?.let { codeChallenge ->
            if (codeVerifier == null) {
                Napier.w("token: client did not provide any code verifier: $codeVerifier for $code")
                throw OAuth2Exception(Errors.INVALID_GRANT, "code verifier invalid: $codeVerifier for $code")
            }
            val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
            if (codeChallenge != codeChallengeCalculated) {
                Napier.w("token: client did not provide correct code verifier: $codeVerifier for $code")
                throw OAuth2Exception(Errors.INVALID_GRANT, "code verifier invalid: $codeVerifier for $code")
            }
        }
    }

    private suspend fun TokenRequestParameters.loadIssuedCode(): IssuedCode? = when (grantType) {
        OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
            if (code == null || !codeService.verifyAndRemove(code!!))
                throw OAuth2Exception(Errors.INVALID_CODE, "code not valid: $code")
                    .also { Napier.w("token: client did not provide correct code: $code") }
            code?.let { codeToUserInfoStore.remove(it) }
        }

        OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
            if (preAuthorizedCode == null || !codeService.verifyAndRemove(preAuthorizedCode!!))
                throw OAuth2Exception(Errors.INVALID_GRANT, "pre-authorized code not valid: $preAuthorizedCode")
                    .also { Napier.w("token: pre-authorized code not valid: $preAuthorizedCode") }
            preAuthorizedCode?.let { codeToUserInfoStore.remove(it) }
        }

        else -> throw OAuth2Exception(INVALID_REQUEST, "grant_type invalid")
            .also { Napier.w("token: client did not provide valid grant_type: $grantType") }
    }

    override suspend fun providePreAuthorizedCode(user: OidcUserInfoExtended): String =
        codeService.provideCode().also {
            codeToUserInfoStore.put(
                it,
                IssuedCode(it, user, strategy.validScopes(), strategy.validAuthorizationDetails())
            )
        }

    /**
     * Get the [OidcUserInfoExtended] (holding [at.asitplus.openid.OidcUserInfo]) associated with the token in
     * [authorizationHeader], that was created before at the Authorization Server.
     *
     * Also validates that the client has really requested a credential (either identified by [credentialIdentifier]
     * or [credentialConfigurationId]) that has been allowed by this access token issued in [token].
     *
     * @param authorizationHeader value of the HTTP header `Authorization`
     * @param dpopHeader value of the HTTP header `DPoP`
     * @param requestUrl public-facing URL that the client has used (to validate `DPoP`)
     * @param requestUrl HTTP method that the client has used (to validate `DPoP`)
     */
    override suspend fun getUserInfo(
        authorizationHeader: String,
        dpopHeader: String?,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        requestUrl: String?,
        requestMethod: HttpMethod?,
    ): KmmResult<OidcUserInfoExtended> = catching {
        val accessToken = tokenService.validateToken(authorizationHeader, dpopHeader, requestUrl, requestMethod)

        val result = accessTokenToUserInfoStore.get(accessToken)
            ?: throw OAuth2Exception(INVALID_TOKEN, "could not load user info for access token $accessToken")
        if (credentialIdentifier != null) {
            if (result.authorizationDetails == null)
                throw OAuth2Exception(INVALID_TOKEN, "no authorization details stored for access token $accessToken")
            val validCredentialIdentifiers = result.authorizationDetails.flatMap { it.credentialIdentifiers ?: setOf() }
            if (!validCredentialIdentifiers.contains(credentialIdentifier))
                throw OAuth2Exception(
                    INVALID_TOKEN,
                    "credential_identifier expected to be in ${validCredentialIdentifiers}, but got $credentialIdentifier"
                )
        } else if (credentialConfigurationId != null) {
            if (result.scope == null)
                throw OAuth2Exception(INVALID_TOKEN, "no scope stored for access token $accessToken")
            if (!result.scope.contains(credentialConfigurationId))
                throw OAuth2Exception(
                    INVALID_TOKEN,
                    "credential_configuration_id expected to be ${result.scope}, but got $credentialConfigurationId"
                )

        } else {
            throw OAuth2Exception(INVALID_TOKEN, "neither credential_identifier nor credential_configuration_id set")
        }

        result.userInfoExtended
            .also { Napier.v("getUserInfo returns $it") }
    }

    override suspend fun provideMetadata() = KmmResult.success(metadata)

}
