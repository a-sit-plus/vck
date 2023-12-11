package at.asitplus.wallet.lib.oidc

/**
 * Container for a OIDC Authentication Request
 */
data class AuthenticationRequest(
    val url: String,
    val params: AuthenticationRequestParameters,
) {

}