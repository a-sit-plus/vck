package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.signum.indispensable.cosef.CoseKey

data class MdocInputValidationSummary(
    val integrityValidationSummary: IntegrityValidationSummary,
) {
    val isSuccess = listOf(
        integrityValidationSummary.isSuccess,
    ).all { it }

    val error = integrityValidationSummary.error

    sealed interface IntegrityValidationSummary {
        val isSuccess: Boolean
        val error: Throwable?

        data object IntegrityNotValidated
            : IntegrityValidationSummary {
            override val isSuccess: Boolean
                get() = false
            override val error: Throwable?
                get() = IllegalArgumentException("No issuer key")
        }

        data class IntegrityValidationResult(
            val issuerKey: CoseKey,
            override val isSuccess: Boolean,
            override val error: Throwable?,
        ) : IntegrityValidationSummary
    }
}