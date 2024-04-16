package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.EmptyCredentialDataProvider
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
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

/**
 * Simple authorization server implementation, to be used for [IssuerService],
 * when issuing credentials directly from a local [dataProvider].
 *
 * Implemented from [OpenID for Verifiable Credential Issuance]
 * (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), Draft 13, 2024-02-08.
 */
class AuthorizationService(
    /**
     * Source of user data.
     */
    private val dataProvider: IssuerCredentialDataProvider = EmptyCredentialDataProvider,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Collection<ConstantIndex.CredentialScheme>,
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
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    override val publicContext: String = "https://wallet.a-sit.at/",
    /**
     * Used to build [IssuerMetadata.authorizationEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [authorize].
     */
    private val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [IssuerMetadata.tokenEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    private val tokenEndpointPath: String = "/token",
) : OpenIdAuthorizationServer {

    private val codeToCodeChallengeMap = mutableMapOf<String, String>()
    private val codeChallengeMutex = Mutex()

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`
     */
    override val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            authorizationEndpointUrl = "$publicContext$authorizationEndpointPath",
            tokenEndpointUrl = "$publicContext$tokenEndpointPath",
        )
    }

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    override suspend fun authorize(request: AuthenticationRequestParameters): KmmResult<AuthenticationResponseResult> {
        // TODO Need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        if (request.redirectUrl == null)
            return KmmResult.failure<AuthenticationResponseResult>(
                OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST, "redirect_uri not set")
            ).also { Napier.w("authorize: client did not set redirect_uri in $request") }
        val code = codeService.provideCode()
        val responseParams = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )
        if (request.codeChallenge != null) {
            codeChallengeMutex.withLock { codeToCodeChallengeMap[code] = request.codeChallenge }
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
    override suspend fun token(params: TokenRequestParameters): KmmResult<TokenResponseParameters> {
        // TODO This is part of the Authorization Server
        when (params.grantType) {
            OpenIdConstants.GRANT_TYPE_CODE -> if (params.code == null || !codeService.verifyCode(params.code))
                return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(OpenIdConstants.Errors.INVALID_CODE))
                    .also { Napier.w("token: client did not provide correct code") }

            OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE -> if (params.preAuthorizedCode == null ||
                !codeService.verifyCode(params.preAuthorizedCode)
            ) return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(OpenIdConstants.Errors.INVALID_GRANT))
                .also { Napier.w("token: client did not provide pre authorized code") }

            else ->
                return KmmResult.failure<TokenResponseParameters>(
                    OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST, "No valid grant_type")
                ).also { Napier.w("token: client did not provide valid grant_type: ${params.grantType}") }
        }
        if (params.authorizationDetails != null) {
            // TODO verify params.authorizationDetails.claims and so on
            params.authorizationDetails.credentialIdentifiers?.forEach { credentialIdentifier ->
                if (!credentialSchemes.map { it.vcType }.contains(credentialIdentifier)) {
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(OpenIdConstants.Errors.INVALID_GRANT))
                        .also { Napier.w("token: client requested invalid credential identifier: $credentialIdentifier") }
                }
            }
        }
        params.codeVerifier?.let { codeVerifier ->
            codeChallengeMutex.withLock { codeToCodeChallengeMap.remove(params.code) }?.let { codeChallenge ->
                val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256()
                    .encodeToString(Base64UrlStrict)
                if (codeChallenge != codeChallengeCalculated) {
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(OpenIdConstants.Errors.INVALID_GRANT))
                        .also { Napier.w("token: client did not provide correct code verifier: $codeVerifier") }
                }
            }
        }
        val result = TokenResponseParameters(
            accessToken = tokenService.provideToken(),
            tokenType = OpenIdConstants.TOKEN_TYPE_BEARER,
            expires = 3600,
            clientNonce = clientNonceService.provideNonce(),
            authorizationDetails = params.authorizationDetails?.let {
                // TODO supported credential identifiers!
                listOf(it)
            }
        )
        Napier.i("token returns $result")
        return KmmResult.success(result)
    }

    override fun providePreAuthorizedCode(): String {
        return codeService.provideCode()
    }

    override fun verifyAndRemoveClientNonce(nonce: String): Boolean {
        return clientNonceService.verifyAndRemoveNonce(nonce)
    }

    override fun getUserInfo(accessToken: String): KmmResult<Unit> {
        if (!tokenService.verifyToken(accessToken)) {
            return KmmResult.failure<Unit>(OAuth2Exception(Errors.INVALID_TOKEN))
                .also { Napier.w("verifyToken: client did not provide correct token: $accessToken") }
        }
        return KmmResult.success(Unit)
    }

}