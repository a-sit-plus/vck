package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

/**
 * A requested ISO namespace/data-element pair found in a credential: a data element of an mdoc, or, for an SD-JWT VC
 * requested with the namespace `_` (WG10 N2933 v2), a claim the data element identifier [claimName] is mapped to.
 */
data class IsoDeviceRetrievalClaimMatch(
    val namespace: String,
    val claimName: String,
    val claimValue: Any,
    /** The claim to disclose, i.e. [namespace] and [claimName] for an mdoc, or the selected claim of an SD-JWT VC. */
    val path: NormalizedJsonPath = NormalizedJsonPath() + namespace + claimName,
)

/**
 * One credential that completely satisfies one `DocRequest`.
 *
 * [credentialIndex] refers to the credential list on [HolderIsoDeviceRetrievalQueryMatchingResult]. Keeping this
 * identity is necessary because several stored credentials may use the same docType.
 */
data class IsoDeviceRetrievalCredentialMatch(
    val credentialIndex: Int,
    val requestedClaims: List<IsoDeviceRetrievalClaimMatch>,
)

/**
 * Matches for an ISO Device Request. Each outer list entry corresponds, by index, to one `DeviceRequest.docRequests`
 * entry; its inner list contains the stored credentials that satisfy every requested data element.
 *
 * The positional model deliberately preserves repeated requests for the same docType.
 */
data class IsoDeviceRetrievalQueryMatchingResult(
    val documentMatches: List<List<IsoDeviceRetrievalCredentialMatch>>,
)
