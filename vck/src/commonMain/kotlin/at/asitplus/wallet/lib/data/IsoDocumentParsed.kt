package at.asitplus.wallet.lib.data

import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorMdoc.verifyDocument] when parsing an ISO document,
 * and also in [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationIsoMdoc].
 */
data class IsoDocumentParsed(
    val document: Document,
    val mso: MobileSecurityObject,
    val validItems: List<IssuerSignedItem> = listOf(),
    val invalidItems: List<IssuerSignedItem> = listOf(),
    val freshnessSummary: CredentialFreshnessSummary.Mdoc,
)