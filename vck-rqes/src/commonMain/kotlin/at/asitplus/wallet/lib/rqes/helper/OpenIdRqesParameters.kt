package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.openid.TransactionData

/**
 * Wrapper to distinguish RQES related [AuthenticationRequestParameter] members better
 */
@Deprecated("Subsumed", ReplaceWith("RqesRequestOptions"))
data class OpenIdRqesParameters(
    val transactionData: List<TransactionData>,
)

