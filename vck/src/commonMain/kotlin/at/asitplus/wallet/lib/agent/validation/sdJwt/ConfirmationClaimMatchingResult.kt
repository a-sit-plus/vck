package at.asitplus.wallet.lib.agent.validation.sdJwt

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.ConfirmationClaim

data class ConfirmationClaimMatchingResult(
    val confirmationClaim: ConfirmationClaim?,
    val publicKey: CryptoPublicKey,
    val isSuccess: Boolean,
)