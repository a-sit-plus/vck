package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.openid.OpenIdConstants.Errors
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
    suspend fun authorize(request: AuthenticationRequestParameters) = catching {
        // TODO Need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        if (request.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST, "redirect_uri not set")
                .also { Napier.w("authorize: client did not set redirect_uri in $request") }

        val code = codeService.provideCode().also {
            val userInfo = dataProvider.loadUserInfo(request)
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
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
        val userInfo: OidcUserInfoExtended = when (params.grantType) {
            OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE -> {
                if (params.code == null || !codeService.verifyCode(params.code))
                    throw OAuth2Exception(Errors.INVALID_CODE)
                        .also { Napier.w("token: client did not provide correct code") }
                codeToUserInfoMutex.withLock { codeToUserInfoMap[params.code] }
            }

            OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> {
                if (params.preAuthorizedCode == null || !codeService.verifyCode(params.preAuthorizedCode))
                    throw OAuth2Exception(Errors.INVALID_GRANT)
                        .also { Napier.w("token: client did not provide pre authorized code") }
                codeToUserInfoMutex.withLock { codeToUserInfoMap[params.preAuthorizedCode] }
            }

            else -> {
                throw OAuth2Exception(Errors.INVALID_REQUEST, "No valid grant_type")
                    .also { Napier.w("token: client did not provide valid grant_type: ${params.grantType}") }
            }
        } ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("token: could not load user info for $params}") }

        // TODO work out mapping of credential identifiers in authorization details to schemes
        val filteredAuthorizationDetails = params.authorizationDetails?.filter {
            credentialSchemes.map { it.vcType }.contains(it.credentialConfigurationId) ||
            credentialSchemes.map { it.sdJwtType }.contains(it.credentialConfigurationId) ||
            credentialSchemes.map { it.isoDocType }.contains(it.credentialConfigurationId)
        }?.toSet()

        params.codeVerifier?.let { codeVerifier ->
            codeToCodeChallengeMutex.withLock { codeToCodeChallengeMap.remove(params.code) }?.let { codeChallenge ->
                val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
                if (codeChallenge != codeChallengeCalculated) {
                    throw OAuth2Exception(Errors.INVALID_GRANT)
                        .also { Napier.w("token: client did not provide correct code verifier: $codeVerifier") }
                }
            }
        }

        TokenResponseParameters(
            accessToken = tokenService.provideToken().also {
                accessTokenToUserInfoMutex.withLock { accessTokenToUserInfoMap[it] = userInfo }
            },
            tokenType = OpenIdConstants.TOKEN_TYPE_BEARER,
            expires = 3600.seconds,
            clientNonce = clientNonceService.provideNonce(),
            authorizationDetails = filteredAuthorizationDetails
        ).also { Napier.i("token returns $it") }
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

    override suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfoExtended> = catching {
        if (!tokenService.verifyToken(accessToken)) {
            throw OAuth2Exception(Errors.INVALID_TOKEN)
                .also { Napier.w("getUserInfo: client did not provide correct token: $accessToken") }
        }
        val result = accessTokenToUserInfoMutex.withLock { accessTokenToUserInfoMap[accessToken] }
            ?: throw OAuth2Exception(Errors.INVALID_TOKEN)
                .also { Napier.w("getUserInfo: could not load user info for $accessToken") }

        result
            .also { Napier.v("getUserInfo returns $it") }
    }

    override suspend fun provideMetadata() = KmmResult.success(metadata)
}