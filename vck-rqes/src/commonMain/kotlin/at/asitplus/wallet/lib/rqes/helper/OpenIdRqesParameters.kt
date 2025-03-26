package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.openid.TransactionData

/**
 * Wrapper to distinguish RQES related [AuthenticationRequestParameter] members better
 */
data class OpenIdRqesParameters(
    val transactionData: Set<TransactionData>,
)

