package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationDetails
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidationDetails
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidationDetails

sealed interface CredentialTimelinessValidationSummary : TimelinessIndicator {
    data class VcJws(
        val details: VcJwsTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary, TimelinessIndicator by details

    data class SdJwt(
        val details: SdJwtTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary, TimelinessIndicator by details

    data class Mdoc(
        val details: MdocTimelinessValidationDetails,
    ) : CredentialTimelinessValidationSummary, TimelinessIndicator by details
}