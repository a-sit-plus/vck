package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Duration.Companion.seconds


/**
 * Simple authorization server implementation, to be used for [CredentialIssuer],
 * when issuing credentials directly from a local [dataProvider].
 *
 * Implemented from [OpenID for Verifiable Credential Issuance]
 * (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), Draft 13, 2024-02-08.
 */
class SimpleAuthorizationService(
    /**
     * Source of user data.
     */
    private val dataProvider: OAuth2DataProvider,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Set<ConstantIndex.CredentialScheme>,
    /**
     * Used to create and verify authorization codes during issuing.
     */
    private val codeService: CodeService = DefaultCodeService(),
    /**
     * Used to create and verify bearer tokens during issuing.
     */
    private val tokenService: TokenService = DefaultTokenService(),
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
    val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [OAuth2AuthorizationServerMetadata.tokenEndpoint], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    val tokenEndpointPath: String = "/token",
) : OAuth2AuthorizationServer {

    private val codeToCodeChallengeMap = mutableMapOf<String, String>()
    private val codeToCodeChallengeMutex = Mutex()

    private val codeToUserInfoMap = mutableMapOf<String, OidcUserInfoExtended>()
    private val codeToUserInfoMutex = Mutex()

    private val accessTokenToUserInfoMap = mutableMapOf<String, OidcUserInfoExtended>()
    private val accessTokenToUserInfoMutex = Mutex()

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`
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
    suspend fun authorize(request: AuthenticationRequestParameters): KmmResult<AuthenticationResponseResult> {
        // TODO Need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        if (request.redirectUrl == null)
            return KmmResult.failure<AuthenticationResponseResult>(
                OAuth2Exception(Errors.INVALID_REQUEST, "redirect_uri not set")
            ).also { Napier.w("authorize: client did not set redirect_uri in $request") }

        val code = codeService.provideCode().also {
            val userInfo = dataProvider.loadUserInfo(request)
                ?: return KmmResult.failure<AuthenticationResponseResult>(OAuth2Exception(Errors.INVALID_REQUEST))
                    .also { Napier.w("authorize: could not load user info from $request") }
            codeToUserInfoMutex.withLock { codeToUserInfoMap[it] = userInfo }
        }
        val responseParams = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )
        if (request.codeChallenge != null) {
            codeToCodeChallengeMutex.withLock { codeToCodeChallengeMap[code] = request.codeChallenge }
        }
        // TODO Also implement POST?
        val url = URLBuilder(request.redirectUrl)
            .apply { responseParams.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()
        val result = AuthenticationResponseResult.Redirect(url, responseParams)
        Napier.i("authorize returns $result")
        return KmmResult.success(result)
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(params: TokenRequestParameters): KmmResult<TokenResponseParameters> {
        val userInfo: OidcUserInfoExtended = when (params.grantType) {
            OpenIdConstants.GRANT_TYPE_CODE -> {
                if (params.code == null || !codeService.verifyCode(params.code))
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_CODE))
                        .also { Napier.w("token: client did not provide correct code") }
                codeToUserInfoMutex.withLock { codeToUserInfoMap[params.code] }
            }

            OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
                if (params.preAuthorizedCode == null || !codeService.verifyCode(params.preAuthorizedCode))
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                        .also { Napier.w("token: client did not provide pre authorized code") }
                codeToUserInfoMutex.withLock { codeToUserInfoMap[params.preAuthorizedCode] }
            }

            else -> {
                return KmmResult.failure<TokenResponseParameters>(
                    OAuth2Exception(Errors.INVALID_REQUEST, "No valid grant_type")
                ).also { Napier.w("token: client did not provide valid grant_type: ${params.grantType}") }
            }
        } ?: return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
            .also { Napier.w("token: could not load user info for $params}") }

        if (params.authorizationDetails != null) {
            // TODO verify params.authorizationDetails.claims and so on
            params.authorizationDetails.credentialIdentifiers?.forEach { credentialIdentifier ->
                if (!credentialSchemes.map { it.vcType }.contains(credentialIdentifier)) {
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                        .also { Napier.w("token: client requested invalid credential identifier: $credentialIdentifier") }
                }
            }
        }
        params.codeVerifier?.let { codeVerifier ->
            codeToCodeChallengeMutex.withLock { codeToCodeChallengeMap.remove(params.code) }?.let { codeChallenge ->
                val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
                if (codeChallenge != codeChallengeCalculated) {
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                        .also { Napier.w("token: client did not provide correct code verifier: $codeVerifier") }
                }
            }
        }

        val result = TokenResponseParameters(
            accessToken = tokenService.provideToken().also {
                accessTokenToUserInfoMutex.withLock { accessTokenToUserInfoMap[it] = userInfo }
            },
            tokenType = OpenIdConstants.TOKEN_TYPE_BEARER,
            expires = 3600.seconds,
            clientNonce = clientNonceService.provideNonce(),
            authorizationDetails = params.authorizationDetails?.let {
                // TODO supported credential identifiers!
                setOf(it)
            }
        )
        return KmmResult.success(result)
            .also { Napier.i("token returns $result") }
    }

    override suspend fun providePreAuthorizedCode(): String? {
        return codeService.provideCode().also {
            val userInfo = dataProvider.loadUserInfo()
                ?: return null.also { Napier.w("authorize: could not load user info from data provider") }
            codeToUserInfoMutex.withLock { codeToUserInfoMap[it] = userInfo }
        }
    }

    override suspend fun verifyAndRemoveClientNonce(nonce: String): Boolean {
        return clientNonceService.verifyAndRemoveNonce(nonce)
    }

    override suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfoExtended> {
        if (!tokenService.verifyToken(accessToken)) {
            return KmmResult.failure<OidcUserInfoExtended>(OAuth2Exception(Errors.INVALID_TOKEN))
                .also { Napier.w("getUserInfo: client did not provide correct token: $accessToken") }
        }
        val result = accessTokenToUserInfoMutex.withLock { accessTokenToUserInfoMap[accessToken] }
            ?: return KmmResult.failure<OidcUserInfoExtended>(OAuth2Exception(Errors.INVALID_TOKEN))
                .also { Napier.w("getUserInfo: could not load user info for $accessToken") }

        return KmmResult.success(result)
            .also { Napier.v("getUserInfo returns $result") }
    }

    override suspend fun provideMetadata() = KmmResult.success(metadata)
}