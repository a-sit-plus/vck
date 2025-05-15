package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

data class VcJwsVerificationResultWrapper(
    val vcJws: VerifiableCredentialJws,
    val freshnessSummary: CredentialFreshnessSummary.VcJws,
)