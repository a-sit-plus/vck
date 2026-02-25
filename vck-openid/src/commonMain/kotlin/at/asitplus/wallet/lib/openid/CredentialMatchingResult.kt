package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ConstraintField
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.wallet.lib.agent.HolderDCQLQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationExchangeQueryMatchingResult
import at.asitplus.wallet.lib.agent.HolderPresentationRequestMatchingResult
import at.asitplus.wallet.lib.agent.PresentationExchangeQueryMatchingResult
import at.asitplus.wallet.lib.data.CredentialPresentationRequest

/**
 * This interface represents the result of matching a [CredentialPresentationRequest]
 * against a list of available credentials
 */
sealed interface CredentialMatchingResult<Credential : Any> {
    val presentationRequest: CredentialPresentationRequest
    val matchingResult: HolderPresentationRequestMatchingResult<Credential>
}

data class PresentationExchangeMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
    override val matchingResult: HolderPresentationExchangeQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential> {
    @Deprecated(
        "Use constructor with presentationRequest and matchingResult",
        level = DeprecationLevel.ERROR
    )
    constructor(
        presentationRequest: CredentialPresentationRequest.PresentationExchangeRequest,
        matchingInputDescriptorCredentials: Map<String, Map<Credential, Map<ConstraintField, NodeList>>>
    ) : this(
        presentationRequest = presentationRequest,
        matchingResult = matchingInputDescriptorCredentials
            .values.flatMap { it.keys }.distinct().toList().let { credentials ->
                HolderPresentationExchangeQueryMatchingResult(
                    credentials = credentials,
                    queryMatchingResult = PresentationExchangeQueryMatchingResult(
                        inputDescriptorMatchingResults = matchingInputDescriptorCredentials.mapValues { (_, matches) ->
                            credentials.map { credential ->
                                KmmResult.catching {
                                    matches[credential] ?: throw IllegalArgumentException("Unknown matching error")
                                }
                            }
                        }
                    )
                )
            }
    )
}


data class DCQLMatchingResult<Credential : Any>(
    override val presentationRequest: CredentialPresentationRequest.DCQLRequest,
    override val matchingResult: HolderDCQLQueryMatchingResult<Credential>,
) : CredentialMatchingResult<Credential> {
    @Deprecated(
        "Use constructor with presentationRequest and matchingResult",
        level = DeprecationLevel.ERROR
    )
    @Suppress("DEPRECATION")
    constructor(
        presentationRequest: CredentialPresentationRequest.DCQLRequest,
        dcqlQueryResult: at.asitplus.openid.dcql.DCQLQueryResult<Credential>,
    ) : this(
        TODO(), TODO() as HolderDCQLQueryMatchingResult<Credential>,
    )
}
