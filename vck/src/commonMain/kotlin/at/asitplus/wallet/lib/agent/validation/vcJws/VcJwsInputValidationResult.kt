package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws

sealed interface VcJwsInputValidationResult {
    val isSuccess: Boolean

    data class ParsingError(
        val input: String,
        val throwable: Throwable,
    ) : VcJwsInputValidationResult {
        override val isSuccess: Boolean
            get() = false
    }

    data class ContentValidationSummary(
        val input: String,
        val parsed: JwsSigned<VerifiableCredentialJws>,
        val isIntegrityGood: Boolean,
        val subjectMatchingResult: SubjectMatchingResult?,
        val contentSemanticsValidationSummary: VcJwsContentSemanticsValidationSummary,
    ) : VcJwsInputValidationResult {
        val payload: VerifiableCredentialJws
            get() = parsed.payload

        override val isSuccess: Boolean
            get() = listOf(
                isIntegrityGood,
                subjectMatchingResult?.isSuccess != false,
                contentSemanticsValidationSummary.isSuccess,
            ).all { it }
    }
}