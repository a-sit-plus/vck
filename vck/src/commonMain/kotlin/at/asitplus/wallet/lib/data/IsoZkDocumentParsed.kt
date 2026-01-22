package at.asitplus.wallet.lib.data

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorMdoc.verifyZkDocument] when parsing an ISO document,
 */
data class IsoZkDocumentParsed(
    val zkDocument: ZkDocument,
    override val validItems: List<ZkSignedItem> = listOf(),
    override val invalidItems: List<ZkSignedItem> = listOf(),
    // TODO: Consider a different freshnessSummary for ZkDocuments
    override val freshnessSummary: CredentialFreshnessSummary.Mdoc
) : IsoDocumentParsed
