package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ConstraintField
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.openid.dcql.DCQLQueryMatchingResult
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.agent.HolderDCQLQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationExchangeQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationRequestMatchingResult
import at.asitplus.wallet.lib.agent.PresentationExchangeQueryMatchingResult
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlin.collections.flatMap

/**
 * This interface represents the result of matching a [CredentialPresentationRequest]
 * against a list of available credentials
 */
sealed interface CredentialMatchingResult<Credential: Any> {
    val presentationRequest: CredentialPresentationRequest
    val matchingResult: HolderPresentationRequestMatchingResult<Credential>
}

data class PresentationExchangeMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    override val matchingResult: HolderPresentationExchangeQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential> {
    @Deprecated("Use constructor with presentationRequest and matchingResult")
    constructor(
        presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
        matchingInputDescriptorCredentials: Map<String, Map<Credential, Map<ConstraintField, NodeList>>>
    ) : this(
        presentationRequest = presentationRequest,
        matchingResult = HolderPresentationExchangeQueryMatchingResult(
            credentials = matchingInputDescriptorCredentials.flatMap { it.value.keys },
            queryMatchingResult = PresentationExchangeQueryMatchingResult(
                matchingInputDescriptorCredentials.mapValues {
                    it.value.map { KmmResult.success(it.value) }
                })
        )
    )
}


data class DCQLMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
    override val matchingResult: HolderDCQLQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential> {
    @Deprecated("Use constructor with presentationRequest and matchingResult")
    @Suppress("UNCHECKED_CAST", "DEPRECATION")
    constructor(
        presentationRequest: CredentialPresentationRequest.DCQLRequest,
        dcqlQueryResult: DCQLQueryResult<Credential>,
    ) : this(
        presentationRequest = presentationRequest,
        matchingResult = HolderDCQLQueryMatchingResult(
            dcqlQueryResult,
            presentationRequest.dcqlQuery.credentials
        ) as HolderDCQLQueryMatchingResult<Credential>
    )
}
