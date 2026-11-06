package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.openid.TokenIntrospectionResponse
import kotlinx.serialization.json.JsonObject

/**
 * Loads the user info for an access token in [RemoteOAuth2AuthorizationServerAdapter.getUserInfo], e.g. from a backend
 * of the credential issuer, keyed by the [TokenIntrospectionResponse.subject].
 */
fun interface LoadOidcUserInfoFun {
    /** @return a JSON object representing [at.asitplus.openid.OidcUserInfo], i.e. with at least `sub` */
    suspend operator fun invoke(
        input: LoadOidcUserInfoFunInput,
    ): KmmResult<JsonObject>
}

data class LoadOidcUserInfoFunInput(
    /** The access token the Wallet sent to the credential endpoint. */
    val token: String,
    /** The active token introspection response of the remote authorization server for [token]. */
    val response: TokenIntrospectionResponse,
)
