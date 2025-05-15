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
data class AuthenticationResponse(
    val params: AuthenticationResponseParameters?,
    val clientMetadata: RelyingPartyMetadata?,
    val jsonWebKeys: Collection<JsonWebKey>?,
    /**
     * If this is set (acc. to ISO/IEC 18013-7:2024), it needs to be set as
     * [at.asitplus.signum.indispensable.josef.JweHeader.agreementPartyUInfo] when encrypting the response.
     */
    val mdocGeneratedNonce: String? = null,
    val error: OAuth2Error? = null,
)