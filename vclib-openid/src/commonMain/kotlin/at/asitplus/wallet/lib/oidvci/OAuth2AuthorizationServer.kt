package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult

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
     * Get the [OidcUserInfo] associated with the [accessToken], that was created before at the Authorization Server.
     */
    suspend fun getUserInfo(accessToken: String): KmmResult<OidcUserInfo>

    // TODO How is this supposed to happen when using an external Authorization Server?
    fun verifyAndRemoveClientNonce(nonce: String): Boolean
}

