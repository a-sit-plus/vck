package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * Possible outcomes of creating the OIDC Authentication Response
 */
sealed class AuthenticationResponseResult {
    /**
     * Wallet returns the [at.asitplus.openid.AuthenticationResponseParameters] as form parameters, which shall be posted to
     * `redirect_uri` of the Relying Party, i.e. clients should execute that POST with [params] to [url].
     */
    data class Post(val url: String, val params: Map<String, String>) : AuthenticationResponseResult()

    /**
     * Wallet returns the [at.asitplus.openid.AuthenticationResponseParameters] as fragment parameters appended to the
     * `redirect_uri` of the Relying Party, i.e. clients should simply open the [url].
     * The [params] (or when applicable the [error]) are also included for further use.
     */
    data class Redirect(
        val url: String,
        val params: AuthenticationResponseParameters? = null,
        val error: OAuth2Error? = null,
    ) : AuthenticationResponseResult()

    /**
     * Wallet uses the digital credentials API to return the [at.asitplus.openid.AuthenticationResponseParameters]
     */
    data class DcApi(val params: AuthenticationResponseParameters) : AuthenticationResponseResult()
}