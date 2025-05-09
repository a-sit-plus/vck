package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.Validator.verifyVpJws] when parsing a verifiable
 * presentation, and also by [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationVcJwt].
 */
data class VerifiablePresentationParsed(
    val id: String,
    val type: String,
    val timelyVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    val untimelyVerifiableCredentials: Collection<VcJwsVerificationResultWrapper> = listOf(),
    val invalidVerifiableCredentials: Collection<String> = listOf(),
) {
    @Suppress("UNUSED")
    @Deprecated("Renamed to represent new validation semantics.", ReplaceWith("untimelyVerifiableCredentials"))
    val revokedVerifiableCredentials
        get() = untimelyVerifiableCredentials

    @Suppress("UNUSED")
    @Deprecated("Renamed to represent new validation semantics.", ReplaceWith("timelyVerifiableCredentials.map { it.vcJws }"))
    val verifiableCredentials
        get() = timelyVerifiableCredentials.map {
            it.vcJws
        }
}

data class VcJwsVerificationResultWrapper(
    val vcJws: VerifiableCredentialJws,
    val tokenStatus: KmmResult<TokenStatus>?,
    val timelinessValidationSummary: CredentialTimelinessValidationSummary.VcJws,
)