package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended

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
     * Get the [OidcUserInfoExtended] (holding [at.asitplus.openid.OidcUserInfo]) associated with the [accessToken],
     * that was created before at the Authorization Server.
     */
    suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfoExtended>

    /**
     * Whether this authorization server includes [at.asitplus.openid.TokenResponseParameters.clientNonce] it its
     * token response, i.e. whether the [CredentialIssuer] needs to verify it using [verifyClientNonce].
     */
    val supportsClientNonce: Boolean

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

