package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

sealed interface TokenStatusValidationResult {
    data class Rejected(val throwable: Throwable) : TokenStatusValidationResult

    data class Invalid(val tokenStatus: TokenStatus) : TokenStatusValidationResult

    data class Valid(val tokenStatus: TokenStatus?) : TokenStatusValidationResult
}