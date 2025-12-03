package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * Intermediate DTO to hold the parsed [clientMetadata] as well as the created [params].
 *
 * Comes in handy when we need to encrypt the response according to keys passed in [jsonWebKeys].
 */
sealed class AuthenticationResponse(
    val clientMetadata: RelyingPartyMetadata?,
    val jsonWebKeys: Collection<JsonWebKey>?,
) {
    class Success(
        val params: AuthenticationResponseParameters,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
    ) : AuthenticationResponse(clientMetadata, jsonWebKeys)

    class Error(
        val error: OAuth2Error,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
    ) : AuthenticationResponse(clientMetadata, jsonWebKeys)
}