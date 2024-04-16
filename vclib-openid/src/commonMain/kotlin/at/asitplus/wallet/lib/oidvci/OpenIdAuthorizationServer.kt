package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult

interface OpenIdAuthorizationServer {
    /**
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    val publicContext: String

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-configuration`
     */
    val metadata: IssuerMetadata

    /**
     * Builds the authentication response.
     */
    suspend fun authorize(request: AuthenticationRequestParameters): KmmResult<AuthenticationResponseResult>

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(params: TokenRequestParameters): KmmResult<TokenResponseParameters>

    fun providePreAuthorizedCode(): String

    fun getUserInfo(accessToken: String): KmmResult<Unit>

    fun verifyAndRemoveClientNonce(nonce: String): Boolean
}
