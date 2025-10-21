package at.asitplus.wallet.lib.data

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.wallet.lib.agent.PresentationExchangeCredentialDisclosure
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.Serializable

/**
 * The credentials that are actually being used to create the verifiable presentation.
 */
@Serializable
sealed interface CredentialPresentation {
    val presentationRequest: CredentialPresentationRequest

    @Serializable
    data class PresentationExchangePresentation(
        override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
        val inputDescriptorSubmissions: Map<String, PresentationExchangeCredentialDisclosure>? = null
    ) : CredentialPresentation

    @Serializable
    data class DCQLPresentation(
        override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
        val credentialQuerySubmissions: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>?,
    ) : CredentialPresentation
}