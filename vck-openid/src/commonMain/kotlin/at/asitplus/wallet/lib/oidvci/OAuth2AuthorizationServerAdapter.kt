package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.*
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenVerificationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult

/**
 * Used in OID4VCI by [CredentialIssuer] to obtain user data when issuing credentials using OID4VCI.
 *
 * Could also be a remote service, then the format of the access tokens
 * is especially important, and needs a matching implementation for [TokenVerificationService].
 */
interface OAuth2AuthorizationServerAdapter {

    /** Used in several fields in [at.asitplus.openid.IssuerMetadata], to provide endpoint URLs to clients. */
    val publicContext: String

    /** How to verify the access tokens that [CredentialIssuer] needs to verify before issuing credentials. */
    val tokenVerificationService: TokenVerificationService

    /** Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate. */
    val metadata: OAuth2AuthorizationServerMetadata

}

