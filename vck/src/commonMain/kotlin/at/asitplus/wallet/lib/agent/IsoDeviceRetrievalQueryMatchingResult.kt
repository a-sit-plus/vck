package at.asitplus.wallet.lib.agent

/** A requested ISO namespace/data-element pair found in an mdoc credential. */
data class IsoDeviceRetrievalClaimMatch(
    val namespace: String,
    val claimName: String,
    val claimValue: Any,
    /**
     * The data element the verifier actually asked for, when it differs from [claimName].
     * Non-null only for an age attestation resolved according to ISO/IEC 18013-5:2021, 7.2.5
     */
    val requestedClaimName: String? = null
) {
    /** A requested data element that no attestation in the credential can answer. */
    data class Unanswered(
        val namespace: String,
        val claimName: String,
    )

}

/**
 * One credential that completely satisfies one `DocRequest`.
 *
 * [credentialIndex] refers to the credential list on [HolderIsoDeviceRetrievalQueryMatchingResult]. Keeping this
 * identity is necessary because several stored credentials may use the same docType.
 * [unansweredClaims] holds the requested age attestations that cannot be answered from this credential
 */
data class IsoDeviceRetrievalCredentialMatch(
    val credentialIndex: Int,
    val requestedClaims: List<IsoDeviceRetrievalClaimMatch>,
    val unansweredClaims: List<IsoDeviceRetrievalClaimMatch.Unanswered> = emptyList()
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
