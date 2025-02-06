package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidvci.*
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Duration.Companion.seconds


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * with the actual authentication and authorization logic implemented in [strategy].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 14, 2024-08-21.
 */
class SimpleAuthorizationService(
    /**
     * Used to load user data and filter authorization details
     */
    private val strategy: AuthorizationServiceStrategy,
    /**
     * Used to create and verify authorization codes during issuing.
     */
    private val codeService: CodeService = DefaultCodeService(),
    /**
     * Used to create and verify bearer tokens during issuing.
     */
    private val tokenService: NonceService = DefaultNonceService(),
    /**
     * Used to provide challenge to clients to include in proof of possession of key material.
     */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /**
     * Used in several fields in [OAuth2AuthorizationServerMetadata], to provide endpoint URLs to clients.
     */
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
    private val codeToCodeChallengeStore: MapStore<String, String> = DefaultMapStore(),
    private val codeToUserInfoStore: MapStore<String, OidcUserInfoExtended> = DefaultMapStore(),
    private val accessTokenToUserInfoStore: MapStore<String, OidcUserInfoExtended> = DefaultMapStore(),
) : OAuth2AuthorizationServerAdapter {

    override val supportsClientNonce: Boolean = true

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`,
     * see [OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION]
     */
    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = publicContext,
            authorizationEndpoint = "$publicContext$authorizationEndpointPath",
            tokenEndpoint = "$publicContext$tokenEndpointPath",
        )
    }

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    suspend fun authorize(request: AuthenticationRequestParameters) = catching {
        // TODO Need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        if (request.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST, "redirect_uri not set")
                .also { Napier.w("authorize: client did not set redirect_uri in $request") }

        val code = codeService.provideCode().also { code ->
            val userInfo = strategy.loadUserInfo(request, code)
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "Could not load user info for code=$code")
                    .also { Napier.w("authorize: could not load user info from $request") }
            codeToUserInfoStore.put(code, userInfo)
        }
        val responseParams = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )
        request.codeChallenge?.let {
            codeToCodeChallengeStore.put(code, it)
        }
        // TODO Also implement POST?
        val url = URLBuilder(request.redirectUrl!!)
            .apply { responseParams.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()

        AuthenticationResponseResult.Redirect(url, responseParams)
            .also { Napier.i("authorize returns $it") }
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(params: TokenRequestParameters) = catching {
        val userInfo: OidcUserInfoExtended = params.loadUserInfo()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "could not load user info for $params")
                .also { Napier.w("token: could not load user info for $params}") }

        params.codeVerifier?.let { codeVerifier ->
            params.code?.let { code ->
                validateCodeChallenge(code, codeVerifier)
            }
        }

        val response = TokenResponseParameters(
            accessToken = tokenService.provideNonce().also {
                // TODO Also store the scope values or authorization details associated with that access token,
                // so it can be verified when issuing a credential
                // e.g. OID4VCI 8.2.
                // The corresponding object in the credential_configurations_supported map MUST contain one of the
                // value(s) used in the scope parameter in the Authorization Request.
                accessTokenToUserInfoStore.put(it, userInfo)
            },
            tokenType = OpenIdConstants.TOKEN_TYPE_BEARER,
            expires = 3600.seconds,
            clientNonce = clientNonceService.provideNonce(),
        )

        if (params.authorizationDetails != null) {
            val filtered = strategy.filterAuthorizationDetails(params.authorizationDetails!!)
            if (filtered.isEmpty())
                throw OAuth2Exception(Errors.INVALID_REQUEST, "No matching authorization details")
            response
                .copy(authorizationDetails = filtered)
                .also { Napier.i("token returns $it") }
        } else if (params.scope != null) {
            val scope = strategy.filterScope(params.scope!!)
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "No matching scope")
            response
                .copy(scope = scope)
                .also { Napier.i("token returns $it") }
        } else {
            Napier.w("token: request can not be parsed: $params")
            throw OAuth2Exception(Errors.INVALID_REQUEST, "neither authorizationdetails nor scope in request")
        }
    }

    private suspend fun validateCodeChallenge(code: String, codeVerifier: String) {
        codeToCodeChallengeStore.remove(code)?.let { codeChallenge ->
            val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
            if (codeChallenge != codeChallengeCalculated) {
                Napier.w("token: client did not provide correct code verifier: $codeVerifier for $code")
                throw OAuth2Exception(Errors.INVALID_GRANT, "code verifier invalid: $codeVerifier for $code")
            }
        }
    }

    private suspend fun TokenRequestParameters.loadUserInfo(): OidcUserInfoExtended? = when (grantType) {
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

        else -> throw OAuth2Exception(Errors.INVALID_REQUEST, "grant_type invalid")
            .also { Napier.w("token: client did not provide valid grant_type: $grantType") }
    }

    override suspend fun providePreAuthorizedCode(user: OidcUserInfoExtended): String =
        codeService.provideCode().also {
            codeToUserInfoStore.put(it, user)
        }

    override suspend fun verifyClientNonce(nonce: String): Boolean =
        clientNonceService.verifyNonce(nonce)

    override suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfoExtended> = catching {
        if (!tokenService.verifyNonce(accessToken)) {
            throw OAuth2Exception(Errors.INVALID_TOKEN, "access token not valid: $accessToken")
                .also { Napier.w("getUserInfo: client did not provide correct token: $accessToken") }
        }
        val result = accessTokenToUserInfoStore.get(accessToken)
            ?: throw OAuth2Exception(Errors.INVALID_TOKEN, "could not load user info for access token $accessToken")
                .also { Napier.w("getUserInfo: could not load user info for $accessToken") }

        result
            .also { Napier.v("getUserInfo returns $it") }
    }

    override suspend fun provideMetadata() = KmmResult.success(metadata)
}
