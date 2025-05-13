package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationDetails
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidationDetails
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidationDetails

sealed interface CredentialTimelinessValidationSummary {
    val isSuccess: Boolean

    data class VcJws(
        val details: VcJwsTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess
            get() = details.isSuccess
    }

    data class SdJwt(
        val details: SdJwtTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess: Boolean
            get() = details.isSuccess
    }

    data class Mdoc(
        val details: MdocTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary {
        override val isSuccess: Boolean
            get() = details.isSuccess
    }
}