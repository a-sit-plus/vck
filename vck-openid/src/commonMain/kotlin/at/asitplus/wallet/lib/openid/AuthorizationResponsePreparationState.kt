package at.asitplus.wallet.lib.openid

import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.dcapi.request.Oid4vpDCAPIRequest
import kotlinx.serialization.Serializable

@Serializable
data class AuthorizationResponsePreparationState(
    val credentialPresentationRequest: CredentialPresentationRequest?,
    val clientMetadata: RelyingPartyMetadata?,
    val oid4vpDCAPIRequest: Oid4vpDCAPIRequest?,
    /** Whether the request object has been verified (if it was signed at all) */
    val requestObjectVerified: Boolean?,
)