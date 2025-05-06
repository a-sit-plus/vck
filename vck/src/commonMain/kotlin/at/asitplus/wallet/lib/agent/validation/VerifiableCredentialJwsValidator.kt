package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import io.github.aakira.napier.Napier

data class VerifiableCredentialJwsValidator(
    val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator,
    val verifiableCredentialJwsContentSemanticsValidator: VerifiableCredentialJwsContentSemanticsValidator,
) {
    fun validate(vcJws: VerifiableCredentialJws): ValidationSummary {
        return ValidationSummary(
            contentSemanticsErrorSummary = verifiableCredentialJwsContentSemanticsValidator.validate(vcJws),
            timelinessErrorSummary = verifiableCredentialJwsTimelinessValidator.validate(vcJws),
        ).also {
            if (it.isSuccess) {
                Napier.d("VC is valid")
            }
        }
    }

    data class ValidationSummary(
        val contentSemanticsErrorSummary: VerifiableCredentialJwsContentSemanticsValidationSummary,
        val timelinessErrorSummary: VerifiableCredentialJwsTimelinessValidationSummary,
    ) {
        val isSuccess = listOf(
            contentSemanticsErrorSummary.isSuccess,
            timelinessErrorSummary.isSuccess,
        ).all { it }
    }
}

