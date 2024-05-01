package at.asitplus.wallet.lib.oidc

/**
 * Possible outcomes of creating the OIDC Authentication Response
 */
sealed class AuthenticationResponseResult {
    /**
     * Wallet returns the [AuthenticationResponseParameters] as form parameters, which shall be posted to
     * `redirect_uri` of the Relying Party, i.e. clients should execute that POST with [params] to [url].
     */
    data class Post(val url: String, val params: Map<String, String>) : AuthenticationResponseResult()

    /**
     * Wallet returns the [AuthenticationResponseParameters] as fragment parameters appended to the
     * `redirect_uri` of the Relying Party, i.e. clients should simply open the [url]. The [params] are also included
     * for further use.
     */
    data class Redirect(val url: String, val params: AuthenticationResponseParameters) : AuthenticationResponseResult()
}