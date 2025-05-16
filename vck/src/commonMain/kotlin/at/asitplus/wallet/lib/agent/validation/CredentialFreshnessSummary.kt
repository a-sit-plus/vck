package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult

sealed interface CredentialFreshnessSummary {
    val isFresh: Boolean
        get() = timelinessValidationSummary.isTimely && tokenStatusValidationResult is TokenStatusValidationResult.Valid

    val timelinessValidationSummary: CredentialTimelinessValidationSummary
    val tokenStatusValidationResult: TokenStatusValidationResult

    data class Mdoc(
        override val timelinessValidationSummary: CredentialTimelinessValidationSummary.Mdoc,
        override val tokenStatusValidationResult: TokenStatusValidationResult
    ) : CredentialFreshnessSummary

    data class SdJwt(
        override val timelinessValidationSummary: CredentialTimelinessValidationSummary.SdJwt,
        override val tokenStatusValidationResult: TokenStatusValidationResult
    ) : CredentialFreshnessSummary

    data class VcJws(
        override val timelinessValidationSummary: CredentialTimelinessValidationSummary.VcJws,
        override val tokenStatusValidationResult: TokenStatusValidationResult
    ) : CredentialFreshnessSummary
}