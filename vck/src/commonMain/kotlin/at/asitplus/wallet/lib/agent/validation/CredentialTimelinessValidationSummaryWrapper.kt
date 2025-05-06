package at.asitplus.wallet.lib.agent.validation

import kotlin.jvm.JvmInline

sealed interface CredentialTimelinessValidationSummaryWrapper {
    val isSuccess: Boolean

    @JvmInline
    value class VerifiableCredential(
        val summary: VerifiableCredentialJwsTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummaryWrapper {
        override val isSuccess
            get() = summary.isSuccess
    }

    @JvmInline
    value class SdJwtCredential(
        override val isSuccess: Boolean
    ) : CredentialTimelinessValidationSummaryWrapper

    @JvmInline
    value class MdocCredential(
        override val isSuccess: Boolean
    ) : CredentialTimelinessValidationSummaryWrapper
}