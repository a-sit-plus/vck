package at.asitplus.wallet.lib.agent.validation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.VerifiableCredentialJws

sealed interface VerifiableCredentialJwsInputValidationResult {
    val isSuccess: Boolean

    data class ParsingError(
        val input: String,
        val throwable: Throwable,
    ) : VerifiableCredentialJwsInputValidationResult {
        override val isSuccess: Boolean
            get() = false
    }

    data class ContentValidationSummary(
        val input: String,
        val parsed: JwsSigned<VerifiableCredentialJws>,
        val isIntegrityGood: Boolean,
        val subjectMatchingResult: SubjectMatchingResult?,
        val contentSemanticsValidationSummary: VerifiableCredentialJwsContentSemanticsValidationSummary,
    ) : VerifiableCredentialJwsInputValidationResult {
        val payload: VerifiableCredentialJws
            get() = parsed.payload

        override val isSuccess: Boolean
            get() = listOf(
                isIntegrityGood,
                subjectMatchingResult?.isSuccess != false,
                contentSemanticsValidationSummary.isSuccess,
            ).all { it }

        data class SubjectMatchingResult(
            val subject: String,
            val publicKey: CryptoPublicKey,
            val isSuccess: Boolean,
        )
    }
}