package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath

data class HolderIsoDeviceRetrievalQueryMatchingResult<Credential : Any>(
    override val credentials: List<Credential>,
    val queryMatchingResult: IsoDeviceRetrievalQueryMatchingResult,
) : HolderPresentationRequestMatchingResult<Credential> {

    /** Matching credentials and required disclosures, grouped in Device Request document order. */
    val documentMatches: List<List<DeviceRequestCredentialDisclosure<Credential>>> =
        queryMatchingResult.documentMatches.mapIndexed { docRequestIndex, matches ->
            matches.map { match ->
                DeviceRequestCredentialDisclosure(
                    docRequestIndex = docRequestIndex,
                    credential = credentials[match.credentialIndex],
                    disclosedAttributes = match.requestedClaims.map {
                        NormalizedJsonPath() + it.namespace + it.claimName
                    },
                )
            }
        }

    /** Selects the highest-priority matching credential for every requested document. */
    fun toDefaultSubmission(): KmmResult<List<DeviceRequestCredentialDisclosure<Credential>>> = catching {
        documentMatches.mapIndexed { docRequestIndex, matches ->
            matches.firstOrNull()
                ?: throw PresentationException("No credential satisfies document request at index $docRequestIndex")
        }
    }
}
