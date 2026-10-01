package at.asitplus.wallet.lib.data

import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import kotlin.jvm.JvmOverloads

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.ValidatorMdoc.verifyDocument] when parsing an ISO document,
 * and also in [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationIsoMdoc].
 */
data class IsoDocumentParsed @JvmOverloads constructor(
    /** Document as received. */
    val document: Document,
    /** MSO as received. */
    val mso: MobileSecurityObject,
    /** All items that have been parsed correctly, i.e. have a matching digest. */
    val validItems: List<IssuerSignedItem> = listOf(),
    @Deprecated("List is always empty, when validation fails, `ValidatorMdoc` will throw instead")
    val invalidItems: List<IssuerSignedItem> = listOf(),
    val freshnessSummary: CredentialFreshnessSummary.Mdoc,
    /** Errors returned from the Wallet: May be items the user did not consent to disclose or doesn't possess. */
    val documentErrors: Map<String, Map<String, Int>> = emptyMap(),
)
