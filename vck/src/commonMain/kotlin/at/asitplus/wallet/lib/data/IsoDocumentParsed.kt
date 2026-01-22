package at.asitplus.wallet.lib.data

import at.asitplus.iso.Item
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary

/**
 * Intermediate interface used by [at.asitplus.wallet.lib.agent.ValidatorMdoc] when parsing an ISO document,
 * and also in [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationIsoMdoc].
 */
interface IsoDocumentParsed {
    val validItems: List<Item>
    val invalidItems: List<Item>
    val freshnessSummary: CredentialFreshnessSummary.Mdoc
}