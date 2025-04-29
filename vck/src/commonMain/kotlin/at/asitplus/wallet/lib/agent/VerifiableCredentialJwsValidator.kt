package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.Configuration
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

data class VerifiableCredentialJwsValidator(
    val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator = Configuration.instance.verifiableCredentialJwsTimelinessValidator,
    val verifiableCredentialJwsStructureValidator: VerifiableCredentialJwsStructureValidator = Configuration.instance.verifiableCredentialJwsStructureValidator,
) {
    fun validate(vcJws: VerifiableCredentialJws): ValidationSummary {
        return ValidationSummary(
            structureErrorSummary = verifiableCredentialJwsStructureValidator.validate(vcJws),
            timelinessErrorSummary = verifiableCredentialJwsTimelinessValidator.validate(vcJws),
        ).also {
            if (it.isSuccess) {
                Napier.d("VC is valid")
            }
        }
    }

    data class ValidationSummary(
        val structureErrorSummary: VerifiableCredentialJwsStructureValidator.ValidationSummary,
        val timelinessErrorSummary: VerifiableCredentialJwsTimelinessValidator.ValidationSummary,
    ) {
        val isSuccess = listOf(
            structureErrorSummary.isSuccess,
            timelinessErrorSummary.isSuccess,
        ).all { it }
    }
}

