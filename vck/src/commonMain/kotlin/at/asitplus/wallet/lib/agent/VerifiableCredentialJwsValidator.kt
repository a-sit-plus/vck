package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

data class VerifiableCredentialJwsValidator(
    val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator,
    val verifiableCredentialJwsStructureValidator: VerifiableCredentialJwsStructureValidator,
) {
    fun validate(vcJws: VerifiableCredentialJws): ValidationSummary {
        return ValidationSummary(
            structureErrorSummary = verifiableCredentialJwsStructureValidator.validate(vcJws),
            timelinessErrorSummary = verifiableCredentialJwsTimelinessValidator.validate(vcJws),
        ).also {
            if (!it.containsErrors) {
                Napier.d("VC is valid")
            }
        }
    }

    data class ValidationSummary(
        val structureErrorSummary: VerifiableCredentialJwsStructureValidator.ValidationSummary,
        val timelinessErrorSummary: VerifiableCredentialJwsTimelinessValidator.ValidationSummary,
    ) {
        val containsErrors = listOf(
            structureErrorSummary.containsErrors,
            timelinessErrorSummary.containsErrors,
        ).any { it }
    }
}