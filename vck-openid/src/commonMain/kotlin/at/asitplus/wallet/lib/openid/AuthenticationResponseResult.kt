package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * Possible outcomes of creating an OpenID Authentication Response, to be sent back to the verifier.
 */
sealed class AuthenticationResponseResult {
    /**
     * Wallet returns the [AuthenticationResponseParameters] as form parameters, which shall be posted to
     * `redirect_uri` of the Relying Party, i.e., clients should execute an HTTP POST with [params] to [url].
     */
    data class Post(
        val url: String,
        val params: Map<String, String>,
    ) : AuthenticationResponseResult()

    /**
     * Wallet returns the [AuthenticationResponseParameters] as fragment parameters appended to the
     * `redirect_uri` of the Relying Party, i.e., clients should simply open the [url].
     * The [params] (or when applicable the [error]) are also included for further use.
     */
    data class Redirect(
        val url: String,
        val params: AuthenticationResponseParameters? = null,
        val error: OAuth2Error? = null,
    ) : AuthenticationResponseResult()

    /**
     * Use the Digital Credential API to return the [AuthenticationResponseParameters] in [params].
     */
    data class DcApi(
        val params: OpenId4VpResponse,
    ) : AuthenticationResponseResult()
}