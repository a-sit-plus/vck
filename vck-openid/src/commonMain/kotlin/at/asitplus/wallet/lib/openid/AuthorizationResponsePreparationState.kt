package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlinx.serialization.Serializable

/**
 * Intermediate result class to display information about the authentication process to the user,
 * i.e., to let them make an informed decision.
 */
@Serializable
data class AuthorizationResponsePreparationState(
    val request: RequestParametersFrom<AuthenticationRequestParameters>,
    /** Extracted from [request], probably fetched remotely. */
    val credentialPresentationRequest: CredentialPresentationRequest?,
    /** Extracted from [request], probably fetched remotely. */
    val clientMetadata: RelyingPartyMetadata?,
    /** Extracted from [request], probably fetched remotely. */
    val jsonWebKeys: Collection<JsonWebKey>?,
    val verifierInfo: List<VerifierInfo>?,
    /** Audience of the presentation to create */
    val audience: String,
) {
    val dcApiCallingOrigin: String?
        get() = (request as? RequestParametersFrom.DcApiRequest)?.callingOrigin

    val responseRequiresEncryption: Boolean
        get() = request.parameters.responseMode?.requiresEncryption == true

}