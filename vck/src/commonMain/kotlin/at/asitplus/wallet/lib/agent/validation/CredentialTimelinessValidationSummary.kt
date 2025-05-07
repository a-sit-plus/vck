package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

data class CredentialTimelinessValidationSummary(
    val tokenStatus: KmmResult<TokenStatus>?,
    val timelinessValidationSummaryDetails: CredentialTimelinessValidationSummaryDetails,
) {
    val isSuccess = tokenStatus?.getOrNull() == TokenStatus.Valid && timelinessValidationSummaryDetails.isSuccess
}