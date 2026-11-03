package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * Used in OID4VCI by [OpenId4VciServer] to obtain user data when issuing credentials using OID4VCI.
 *
 * Could also be a remote service, then implementers need to make calls to the remote service.
 */
interface OAuth2AuthorizationServerAdapter {

    /** Used in several fields in [at.asitplus.openid.IssuerMetadata], to provide endpoint URLs to clients. */
    val publicContext: String

    /** Provide necessary [OAuth2AuthorizationServerMetadata] JSON for a client to be able to authenticate. */
    suspend fun metadata(): OAuth2AuthorizationServerMetadata

    /**
     * Obtains information about the token, either by performing token introspection,
     * or by decoding the access token directly (if it is an [at.asitplus.wallet.lib.oauth2.OpenId4VciAccessToken]).
     */
    suspend fun getTokenInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<TokenInfo>

    /**
     * Obtains a JSON object representing [at.asitplus.openid.OidcUserInfo] from the Authorization Server,
     * with the wallet's access token in [authorizationHeader]
     * (which the implementation may need to exchange at the AS first).
     */
    suspend fun getUserInfo(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<JsonObject>

    /** Validates the access token sent to [OpenId4VciServer.credential]. */
    suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
    ): KmmResult<ValidatedAccessToken>

    /** If this is an internal AS, provide a fresh DPoP nonce for clients. */
    suspend fun getDpopNonce(): String?

}


/**
 * Internal data class for a token introspection result
 */
@Serializable
data class TokenInfo(
    val token: String,
    val authorizationDetails: Set<AuthorizationDetails>? = null,
    val scope: String? = null,
    /**
     * Confirmation of the key a DPoP-bound token is bound to, i.e. its JWK SHA-256 thumbprint in `jkt`
     * ([RFC 9449 6.](https://datatracker.ietf.org/doc/html/rfc9449#section-6)). Before granting access with this
     * token, check that the DPoP proof of the request is signed with that key
     * ([RFC 9449 7.1](https://datatracker.ietf.org/doc/html/rfc9449#section-7.1)).
     */
    val confirmationClaim: ConfirmationClaim? = null,
)