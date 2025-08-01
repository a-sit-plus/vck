package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.JwsSigned

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorVcJws.verifyVpJws] when parsing a verifiable
 * presentation, and also by [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationVcJwt].
 */
data class VerifiablePresentationParsed(
    val jws: JwsSigned<VerifiablePresentationJws>,
    val id: String,
    val type: String,
    val freshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    /** This list may contain credentials where evaluation of the token status failed. */
    val notVerifiablyFreshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    val invalidVerifiableCredentials: Collection<String> = listOf(),
)

