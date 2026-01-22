package at.asitplus.wallet.lib.data

import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorMdoc.verifyPlainDocument] when parsing an ISO document,
 */
data class IsoPlainDocumentParsed(
    val document: Document,
    val mso: MobileSecurityObject,
    override val validItems: List<IssuerSignedItem> = listOf(),
    override val invalidItems: List<IssuerSignedItem> = listOf(),
    override val freshnessSummary: CredentialFreshnessSummary.Mdoc,
) : IsoDocumentParsed