package at.asitplus.wallet.lib.data

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.Validator.verifyVpJws] when parsing a verifiable
 * presentation, and also by [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentation].
 */
data class VerifiablePresentationParsed(
    val id: String,
    val type: String,
    val verifiableCredentials: Collection<VerifiableCredentialJws> = listOf(),
    val revokedVerifiableCredentials: Collection<VerifiableCredentialJws> = listOf(),
    val invalidVerifiableCredentials: Collection<String> = listOf(),
)