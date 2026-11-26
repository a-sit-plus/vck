package at.asitplus.wallet.lib.agent

/** A requested ISO namespace/data-element pair found in an mdoc credential. */
data class IsoDeviceRetrievalClaimMatch(
    val namespace: String,
    val claimName: String,
    val claimValue: Any,
)

/**
 * One credential that completely satisfies one `DocRequest`.
 *
 * [credentialIndex] refers to the credential list on [HolderIsoDeviceRetrievalQueryMatchingResult]. Keeping this
 * identity is necessary because several stored credentials may use the same docType.
 */
data class IsoDeviceRetrievalCredentialMatch(
    val credentialIndex: Int,
    /**
     * The data elements to disclose: each requested one, or, if the credential lacks it, its first alternative element
     * set the credential has (ISO/IEC DIS 18013-5:2026, 10.2.4), each data element once.
     */
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
