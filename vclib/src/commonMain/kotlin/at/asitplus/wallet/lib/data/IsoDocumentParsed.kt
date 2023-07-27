package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.iso.IssuerSignedItem

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.Validator.verifyDocument] when parsing an ISO document.
 */
data class IsoDocumentParsed(
    val validItems: List<IssuerSignedItem> = listOf(),
    val invalidItems: List<IssuerSignedItem> = listOf(),
)