package at.asitplus.wallet.lib.agent.validation.common

import at.asitplus.signum.indispensable.CryptoPublicKey

data class SubjectMatchingResult(
    val subject: String,
    val publicKey: CryptoPublicKey,
    val isSuccess: Boolean,
)