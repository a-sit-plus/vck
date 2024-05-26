package at.asitplus.wallet.lib.oidc

/**
 * Intermediate DTO to hold the parsed [clientMetadata] as well as the created [params].
 *
 * Comes in handy when we need to encrypt the response according to keys passed in [clientMetadata].
 */
data class AuthenticationResponse(
    val params: AuthenticationResponseParameters,
    val clientMetadata: RelyingPartyMetadata,
)
