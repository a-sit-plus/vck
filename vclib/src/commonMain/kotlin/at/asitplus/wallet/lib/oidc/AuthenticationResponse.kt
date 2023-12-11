package at.asitplus.wallet.lib.oidc

/**
 * Container for an OIDC Authentication Response
 */
data class AuthenticationResponse(
    val url: String,
    val params: AuthenticationResponseParameters,
) {
}