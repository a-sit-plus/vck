package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import kotlin.jvm.JvmOverloads


/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorVcJws.verifyVpJws] when parsing a verifiable
 * presentation, and also by [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationVcJwt].
 */
data class VerifiablePresentationParsed @JvmOverloads constructor(
    val jws: JwsCompactTyped<VerifiablePresentationJws, JwsHeader>,
    val id: String,
    val type: String,
    val freshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    /** This list may contain credentials where evaluation of the token status failed. */
    val notVerifiablyFreshVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    val invalidVerifiableCredentials: Collection<String> = listOf(),
)
