package at.asitplus.wallet.lib.agent

/**
 * Candidates found by matching a presentation request against a holder's credential store.
 *
 * Implementations keep the query-language-specific matching details, while [credentials] is the ordered store
 * snapshot referenced by those details. A matching result is not a submission and does not disclose anything by
 * itself; the wallet can use it to obtain consent and construct a [at.asitplus.wallet.lib.data.CredentialPresentation].
 */
interface HolderPresentationRequestMatchingResult<Credential: Any> {
    /** Ordered credential snapshot against which the request was matched. */
    val credentials: List<Credential>
}
