package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Used by [CredentialIssuer] to obtain user data when issuing credentials using OID4VCI.
 */
interface OAuth2AuthorizationServer {
    /**
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    val publicContext: String

    /**
     * Provide a pre-authorized code (for flow defined in OID4VCI), to be used by the Wallet implementation
     * to load credentials.
     */
    suspend fun providePreAuthorizedCode(): String?

    /**
     * Get the [OidcUserInfoExtended] (holding [OidcUserInfo]) associated with the [accessToken],
     * that was created before at the Authorization Server.
     */
    suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfoExtended>

    // TODO How is this supposed to happen when using an external Authorization Server?
    suspend fun verifyAndRemoveClientNonce(nonce: String): Boolean

    /**
     * Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate
     */
    suspend fun provideMetadata(): KmmResult<OAuth2AuthorizationServerMetadata>
}

