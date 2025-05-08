package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidationSummary

sealed interface CredentialTimelinessValidationSummary {
    val credential: CredentialWrapper
    val isSuccess: Boolean

    data class VcJws(
        override val credential: CredentialWrapper.VcJws,
        val summary: VcJwsTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess
            get() = summary.isSuccess
    }

    data class SdJwt(
        override val credential: CredentialWrapper.SdJwt,
        val summary: SdJwtTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess: Boolean
            get() = summary.isSuccess
    }

    data class Mdoc(
        override val credential: CredentialWrapper.Mdoc,
        val summary: MdocTimelinessValidationSummary,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess: Boolean
            get() = summary.isSuccess
    }
}