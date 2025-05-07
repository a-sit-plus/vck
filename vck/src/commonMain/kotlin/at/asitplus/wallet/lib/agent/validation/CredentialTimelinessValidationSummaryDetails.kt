package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.SubjectCredentialStore

sealed interface CredentialTimelinessValidationSummaryDetails {
    val storeEntry: SubjectCredentialStore.StoreEntry
    val isSuccess: Boolean

    data class VerifiableCredential(
        override val storeEntry: SubjectCredentialStore.StoreEntry.Vc,
        val summary: VcJwsTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummaryDetails {
        override val isSuccess
            get() = summary.isSuccess
    }

    data class SdJwtCredential(
        override val storeEntry: SubjectCredentialStore.StoreEntry.SdJwt,
        override val isSuccess: Boolean
    ) : CredentialTimelinessValidationSummaryDetails

    data class MdocCredential(
        override val storeEntry: SubjectCredentialStore.StoreEntry.Iso,
        override val isSuccess: Boolean
    ) : CredentialTimelinessValidationSummaryDetails
}