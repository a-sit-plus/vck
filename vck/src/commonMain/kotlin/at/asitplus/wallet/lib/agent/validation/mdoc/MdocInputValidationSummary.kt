package at.asitplus.wallet.lib.agent.validation.mdoc

data class MdocInputValidationSummary(
    val integrityValidationSummary: IntegrityValidationSummary,
) {
    val isSuccess = listOf(
        integrityValidationSummary.isSuccess,
    ).all { it }

    val error = integrityValidationSummary.error

    // ponytail: only one implementation left, since the issuer key is now resolved during verification instead
    // of being passed in, kept sealed to leave room for further integrity checks
    sealed interface IntegrityValidationSummary {
        val isSuccess: Boolean
        val error: Throwable?

        data class IntegrityValidationResult(
            override val isSuccess: Boolean,
            override val error: Throwable?,
        ) : IntegrityValidationSummary
    }
}
