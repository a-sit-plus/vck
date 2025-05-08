package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.signum.indispensable.cosef.CoseKey

data class MdocInputValidationSummary(
    val integrityValidationSummary: IntegrityValidationSummary,
) {
    val isSuccess = listOf(
        integrityValidationSummary.isSuccess,
    ).all { it }

    sealed interface IntegrityValidationSummary {
        val isSuccess: Boolean

        data object IntegrityNotValidated : IntegrityValidationSummary {
            override val isSuccess: Boolean
                get() = false
        }

        data class IntegrityValidationResult(
            val issuerKey: CoseKey,
            override val isSuccess: Boolean,
        ) : IntegrityValidationSummary
    }
}