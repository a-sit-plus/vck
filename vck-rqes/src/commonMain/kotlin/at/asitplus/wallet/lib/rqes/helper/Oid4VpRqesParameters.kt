package at.asitplus.wallet.lib.rqes.helper

import at.asitplus.rqes.collection_entries.TransactionData

/**
 * Wrapper to distinguish RQES related [AuthenticationRequestParameter] members better
 */
data class Oid4VpRqesParameters(
    val transactionData: Set<TransactionData>,
)

