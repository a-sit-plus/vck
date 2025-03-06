package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import io.ktor.http.HttpMethod

/**
 * Used in OID4VCI by [CredentialIssuer] to obtain user data when issuing credentials using OID4VCI.
 *
 * Could also be a remote service
 */
interface OAuth2AuthorizationServerAdapter {

    /**
     * Used in several fields in [at.asitplus.openid.IssuerMetadata], to provide endpoint URLs to clients.
     */
    val publicContext: String

    /**
     * Provide a pre-authorized code (for flow defined in OID4VCI), to be used by the Wallet implementation
     * to load credentials.
     */
    suspend fun providePreAuthorizedCode(user: OidcUserInfoExtended): String

    /**
     * Get the [OidcUserInfoExtended] (holding [at.asitplus.openid.OidcUserInfo]) associated with the access token in
     * [authorizationHeader], that was created before at the Authorization Server.
     *
     * @param authorizationHeader value of the HTTP header `Authorization`
     * @param dpopHeader value of the HTTP header `DPoP`
     * @param requestUrl public-facing URL that the client has used (to validate `DPoP`)
     * @param requestUrl HTTP method that the client has used (to validate `DPoP`)
     */
    suspend fun getUserInfo(
        authorizationHeader: String,
        dpopHeader: String?,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        requestUrl: String? = null,
        requestMethod: HttpMethod? = null,
    ): KmmResult<OidcUserInfoExtended>

    /**
     * Whether this authorization server includes [at.asitplus.openid.TokenResponseParameters.clientNonce] it its
     * token response, i.e. whether the [CredentialIssuer] needs to verify it using [verifyClientNonce].
     */
    val supportsClientNonce: Boolean

    /**
     * Whether this authorization server implements pushed authorization requests as defined in
     * [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html).
     */
    val supportsPushedAuthorizationRequests: Boolean

    /**
     * Called by [CredentialIssuer] to verify that nonces contained in proof-of-possession statements from clients
     * are indeed valid.
     */
    suspend fun verifyClientNonce(nonce: String): Boolean

    /**
     * Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate
     */
    suspend fun provideMetadata(): KmmResult<OAuth2AuthorizationServerMetadata>
}

