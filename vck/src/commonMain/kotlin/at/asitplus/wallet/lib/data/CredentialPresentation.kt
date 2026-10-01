package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.PresentationExchangeCredentialDisclosure
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.Serializable

/**
 * A holder's submission instructions for fulfilling a [CredentialPresentationRequest].
 *
 * This is the boundary between matching and response creation: it carries the credentials and disclosures selected
 * by the user, but not yet the signed presentations or protocol response parameters. A `null` submission asks the
 * holder to match its store and derive the format-specific default during presentation creation.
 */
@Serializable
sealed interface CredentialPresentation {

    /** The verifier request against which the submission is checked. */
    val presentationRequest: CredentialPresentationRequest

    @Suppress("DEPRECATION")
    @Deprecated("Support for Presentation Exchange been removed from OpenID4VP")
    @Serializable
    data class PresentationExchangePresentation(
        override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
        val inputDescriptorSubmissions: Map<String, PresentationExchangeCredentialDisclosure<SubjectCredentialStore.StoreEntry>>? = null
    ) : CredentialPresentation

    /** DCQL submissions keyed by credential query identifier, as required for an OpenID4VP DCQL `vp_token`. */
    @Serializable
    data class DCQLPresentation(
        override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
        val credentialQuerySubmissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>?,
    ) : CredentialPresentation

    /** Holder selections for creating one ISO Device Response. */
    @Serializable
    data class IsoDeviceRetrievalPresentation(
        override val presentationRequest: CredentialPresentationRequest.IsoDeviceRetrieval,
        val submissions: Collection<DeviceRequestCredentialDisclosure<SubjectCredentialStore.StoreEntry>>? = null,
    ) : CredentialPresentation
}
