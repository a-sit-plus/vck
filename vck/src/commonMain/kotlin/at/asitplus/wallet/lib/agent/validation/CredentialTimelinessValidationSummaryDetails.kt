package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidationSummary

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
        val summary: SdJwtTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummaryDetails {
        override val isSuccess: Boolean
            get() = summary.isSuccess
    }

    data class MdocCredential(
        override val storeEntry: SubjectCredentialStore.StoreEntry.Iso,
        val summary: MdocTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummaryDetails {
        override val isSuccess: Boolean
            get() = summary.isSuccess
    }
}