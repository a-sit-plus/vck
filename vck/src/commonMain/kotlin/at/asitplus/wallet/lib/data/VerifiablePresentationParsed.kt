package at.asitplus.wallet.lib.data

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorVcJws.verifyVpJws] when parsing a verifiable
 * presentation, and also by [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationVcJwt].
 */
data class VerifiablePresentationParsed(
    val id: String,
    val type: String,
    val freshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    /**
     * This list may contain credentials where evaluation of the token status failed.
     */
    val notVerifiablyFreshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    val invalidVerifiableCredentials: Collection<String> = listOf(),
) {
    @Suppress("UNUSED")
    @Deprecated("Renamed to represent new validation semantics.", ReplaceWith("freshVerifiableCredentials.map { it.vcJws }"))
    val verifiableCredentials
        get() = freshVerifiableCredentials.map {
            it.vcJws
        }

    @Suppress("UNUSED")
    @Deprecated("Renamed to represent new validation semantics.", ReplaceWith("notVerifiablyFreshVerifiableCredentials"))
    val revokedVerifiableCredentials
        get() = notVerifiablyFreshVerifiableCredentials
}

