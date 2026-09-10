package at.asitplus.wallet.lib.agent

import at.asitplus.dif.ConstraintField
import at.asitplus.jsonpath.core.NodeList

typealias InputDescriptorMatching = Map<ConstraintField, NodeList>

/**
 * Holder-facing view of a Presentation Exchange match.
 *
 * [queryMatchingResult] identifies matches by their index in [credentials]. [inputDescriptorMatches] resolves those
 * indices to actual credentials and exposes the matching JSON paths for disclosure selection.
 */
@Suppress("DEPRECATION")
@Deprecated("Support for Presentation Exchange has been removed from OpenID4VP; use DCQL or DeviceRequest")
data class HolderPresentationExchangeQueryMatchingResult<Credential: Any>(
    override val credentials: List<Credential>,
    val queryMatchingResult: PresentationExchangeQueryMatchingResult
): HolderPresentationRequestMatchingResult<Credential> {
    val inputDescriptorMatches = queryMatchingResult.inputDescriptorMatches.mapValues {
        it.value.mapKeys {
            credentials[it.key.toInt()]
        }
    }

    /**
     * Selects the first matching credential for every input descriptor and the first matching JSON path for each
     * constraint field. Callers can instead construct their own map when the user chooses another credential or a
     * different disclosure. The resulting submission is validated when the presentation is created.
     */
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
