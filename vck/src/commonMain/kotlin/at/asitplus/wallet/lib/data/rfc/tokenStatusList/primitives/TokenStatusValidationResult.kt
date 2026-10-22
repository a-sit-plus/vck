@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

@Deprecated("Status is validated by at.asitplus.wallet.lib.validation.CredentialValidator with a StatusValidator and a StatusListTokenResolver. To be removed in the next major release.")
sealed interface TokenStatusValidationResult {
    data class Rejected(val throwable: Throwable) : TokenStatusValidationResult

    data class Invalid(val tokenStatus: TokenStatus) : TokenStatusValidationResult

    data class Valid(val tokenStatus: TokenStatus?) : TokenStatusValidationResult
}