package at.asitplus.wallet.lib.agent

import at.asitplus.dif.ConstraintField
import at.asitplus.jsonpath.core.NodeList

typealias InputDescriptorMatching = Map<ConstraintField, NodeList>

data class HolderPresentationExchangeQueryMatchingResult<Credential: Any>(
    override val credentials: List<Credential>,
    val queryMatchingResult: PresentationExchangeQueryMatchingResult
): HolderPresentationRequestMatchingResult<Credential> {
    val inputDescriptorMatches = queryMatchingResult.inputDescriptorMatches.mapValues {
        it.value.mapKeys {
            credentials[it.key.toInt()]
        }
    }

    fun toDefaultSubmission(): Map<String, PresentationExchangeCredentialDisclosure<Credential>> =
        inputDescriptorMatches.mapNotNull { descriptorCredentialMatches ->
            descriptorCredentialMatches.value.entries.firstNotNullOfOrNull { (credential, matching) ->
                PresentationExchangeCredentialDisclosure(
                    credential = credential,
                    disclosedAttributes = matching.values.mapNotNull {
                        it.firstOrNull()?.normalizedJsonPath
                    },
                )
            }?.let {
                descriptorCredentialMatches.key to it
            }
        }.toMap()
}

