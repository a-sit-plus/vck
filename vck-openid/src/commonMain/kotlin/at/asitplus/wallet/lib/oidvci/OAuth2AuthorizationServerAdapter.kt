package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult

/**
 * Used in OID4VCI by [CredentialIssuer] to obtain user data when issuing credentials using OID4VCI.
 *
 * Could also be a remote service, then implementers need to make calls to the remote service.
 */
interface OAuth2AuthorizationServerAdapter {

    /** Used in several fields in [at.asitplus.openid.IssuerMetadata], to provide endpoint URLs to clients. */
    val publicContext: String

    /** How to verify the access tokens that [CredentialIssuer] needs to verify before issuing credentials. */
    @Deprecated("Use [userInfo] instead")
    val tokenVerificationService: TokenVerificationService

    @Deprecated("Use [metadata()] instead")
    /** Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate. */
    val metadata: OAuth2AuthorizationServerMetadata

    /** Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate. */
    suspend fun metadata(): OAuth2AuthorizationServerMetadata

    /**
     * Obtains [at.asitplus.openid.OidcUserInfoExtended] from the Authorization Server, for which the AS will
     * verify the access token sent by the client (either directly, or with a token exchange step before).
     */
    suspend fun userInfo(
        authorizationHeader: String,
        credentialIdentifier: String?,
        credentialConfigurationId: String?,
        request: RequestInfo?,
    ): KmmResult<OidcUserInfoExtended>

}

