package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.signum.indispensable.CryptoPublicKey

data class VcJwsToVpJwsMappingValidationSummary(
    val inconsistentIssuerError: InconsistentIssuerError?,
    val inconsistentPublicKeyError: InconsistentPublicKeyError?,
) {
    val isSuccess = listOf(
        inconsistentIssuerError == null,
        inconsistentPublicKeyError == null,
    ).all { it }

    data class InconsistentIssuerError(
        val vcSubject: String,
        val vpIssuer: String,
    )
    data class InconsistentPublicKeyError(
        val vcSubject: String,
        val vpPublicKey: CryptoPublicKey,
    )
}